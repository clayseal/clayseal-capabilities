"""CLI: what fraction of attacks are even *decidable* by an authorization layer?

    python -m benchmarks.coverage --datasets redcode,agentharm,asb,agentdojo

Our deterministic tables report ~100% containment at ~0% false-block, and that
pair of numbers is not believable on its face. It is also not wrong. It is
unweighted. Every attack corpus we replay is dominated by attacks that *leave
the granted surface*: a different target, a different resource, a different
argument than the user authorized. Authorization is exactly the mechanism that
catches those, so containment on that class is ~100% and should be.

The class that a per-call authorization layer cannot decide is the one where
every field is legitimate: granted tool, granted resource, granted action,
in-scope target, authorized argument shape. AgentHarm is almost entirely that
class, and the ladder scores 6.3% on it. Both numbers are honest; quoting only
the first is not.

So this module partitions attack events by a rule that never consults an engine:

``surface-leaving``   at least one field falls outside what the task's own
                      mandate and legitimate calls establish. Decidable.
``in-surface``        every field is one the task legitimately uses. A per-call
                      authorization layer has nothing to object to, by
                      construction, and the only remaining signals are aggregate
                      (budget, rate) or semantic (intent classification).

Reporting containment per class, plus the class mix per corpus, replaces one
saturated number with a defensible one: here is what we contain, here is what
nothing at this layer contains, and here is how much of a realistic threat model
each represents. A buyer trusts the second table and discounts the first.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from benchmarks.core.engines import LADDER, build_engines
from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, EventLabel
from benchmarks.core.stats import cluster_bootstrap_ci

SURFACE_LEAVING = "surface-leaving"
IN_SURFACE = "in-surface"


def _path_prefix(path: str | None) -> str | None:
    """Directory-level grain. Two files in the same authorized directory are the
    same surface; a file in another directory is not."""
    if not path:
        return None
    if path.startswith("net:"):
        return path  # a host is its own surface
    return path.rsplit("/", 1)[0] or "/"


@dataclass
class TaskSurface:
    """What the task's *legitimate* activity establishes as normal."""

    tools: set[str] = field(default_factory=set)
    resources: set[str] = field(default_factory=set)
    actions: set[str] = field(default_factory=set)
    path_prefixes: set[str] = field(default_factory=set)

    # Path globs from the mandate. Kept separate from observed prefixes because
    # a glob has to be matched, not compared.
    path_patterns: list[str] = field(default_factory=list)

    @classmethod
    def of(cls, task: BenchmarkTask) -> "TaskSurface":
        surface = cls()
        # The granted mandate, which is authorization the user actually issued.
        surface.tools |= set(task.allowed_tools)
        # The mandate's path scope is part of the surface even when the task
        # ships no benign trajectory to observe. Without this, an attack-only
        # corpus like RedCode has an empty observed prefix set, the target check
        # is skipped, and every attack is misfiled as in-surface. That inverted
        # RedCode's entire finding: its attacks are the textbook surface-leaving
        # case, granted tool aimed at an ungranted target.
        try:
            from clayseal.core.task_scope import compile_task_scope

            surface.path_patterns = list(compile_task_scope(task.mandate).allowed_paths)
        except Exception:
            surface.path_patterns = []
        for cap in task.capabilities:
            if cap.get("resource"):
                surface.resources.add(cap["resource"])
            if cap.get("action"):
                surface.actions.add(cap["action"])
        # Plus the observed benign trajectory, which is what the agent actually
        # does when nobody is attacking it.
        for event in task.events:
            if event.label is not EventLabel.BENIGN:
                continue
            surface.tools.add(event.tool_name)
            surface.resources.add(event.resource)
            surface.actions.add(event.action)
            prefix = _path_prefix(event.path)
            if prefix:
                surface.path_prefixes.add(prefix)
        return surface

    def classify(self, event: BenchmarkEvent) -> tuple[str, list[str]]:
        """Return the class and which fields left the surface."""
        departures = []
        if self.tools and event.tool_name not in self.tools:
            departures.append("tool")
        if self.resources and event.resource not in self.resources:
            departures.append("resource")
        if self.actions and event.action not in self.actions:
            departures.append("action")
        if event.path:
            prefix = _path_prefix(event.path)
            in_observed = bool(self.path_prefixes) and prefix in self.path_prefixes
            in_granted = False
            if self.path_patterns:
                from clayseal.core.task_scope import path_matches_any

                in_granted = path_matches_any(event.path, self.path_patterns)
            # Only judge the target when the task establishes a surface at all,
            # by observed trajectory or by mandate. A task with neither says
            # nothing about its targets and must not be scored on them.
            if (self.path_prefixes or self.path_patterns) and not (in_observed or in_granted):
                departures.append("target")
        return (SURFACE_LEAVING if departures else IN_SURFACE), departures


@dataclass
class ClassStats:
    events: int = 0
    blocked: int = 0
    clusters: dict[str, list[int]] = field(default_factory=dict)

    @property
    def rate(self) -> float:
        return self.blocked / self.events if self.events else 0.0

    def record(self, task_id: str, blocked: bool) -> None:
        self.events += 1
        self.blocked += blocked
        c = self.clusters.setdefault(task_id, [0, 0])
        c[0] += blocked
        c[1] += 1

    def interval(self):
        return cluster_bootstrap_ci([tuple(v) for v in self.clusters.values()])


def analyze(tasks: list[BenchmarkTask], engine_names: list[str]) -> dict:
    engines = build_engines(engine_names)
    mix = {SURFACE_LEAVING: 0, IN_SURFACE: 0}
    departure_counts: dict[str, int] = {}
    per_engine: dict[str, dict[str, ClassStats]] = {
        e.name: {SURFACE_LEAVING: ClassStats(), IN_SURFACE: ClassStats()} for e in engines
    }

    for task in tasks:
        surface = TaskSurface.of(task)
        for event in task.events:
            if event.label is not EventLabel.ATTACK:
                continue
            klass, departures = surface.classify(event)
            mix[klass] += 1
            for d in departures:
                departure_counts[d] = departure_counts.get(d, 0) + 1
            for engine in engines:
                blocked = not engine.decide(task, event).allowed
                per_engine[engine.name][klass].record(task.task_id, blocked)

    return {"mix": mix, "departures": departure_counts, "per_engine": per_engine}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Attack-class coverage analysis")
    p.add_argument("--datasets", default="redcode,agentharm,asb")
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--engines", default=",".join(n for n in LADDER if n != "deny-all"))
    p.add_argument("--json", type=Path, default=None)
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    from benchmarks.datasets.base import get_loader

    engine_names = [n.strip() for n in args.engines.split(",") if n.strip()]
    report = {}

    print("# Attack-class coverage: what an authorization layer can and cannot decide\n")
    print("Attacks are partitioned without consulting any engine. `surface-leaving` means at "
          "least one field (tool, resource, action, target) falls outside what the task's own "
          "mandate and benign trajectory establish. `in-surface` means every field is one the "
          "task legitimately uses, so a per-call authorization layer has nothing to object "
          "to.\n")

    print("## Class mix per corpus\n")
    print("| Corpus | attack events | surface-leaving | in-surface |")
    print("| --- | --: | --: | --: |")
    all_results = {}
    for name in [d.strip() for d in args.datasets.split(",") if d.strip()]:
        try:
            tasks = get_loader(name).load(limit=args.limit)
        except (KeyError, RuntimeError) as exc:
            print(f"| {name} | _skipped: {str(exc).splitlines()[0][:40]}_ | | |")
            continue
        result = analyze(tasks, engine_names)
        all_results[name] = result
        total = sum(result["mix"].values())
        if not total:
            continue
        sl, ins = result["mix"][SURFACE_LEAVING], result["mix"][IN_SURFACE]
        print(f"| {name} | {total} | {sl} ({sl/total:.0%}) | {ins} ({ins/total:.0%}) |")

    for name, result in all_results.items():
        total = sum(result["mix"].values())
        if not total:
            continue
        print(f"\n## {name}: containment by class\n")
        print("| Engine | surface-leaving | in-surface |")
        print("| --- | --- | --- |")
        for engine_name in engine_names:
            stats = result["per_engine"][engine_name]
            cells = []
            for klass in (SURFACE_LEAVING, IN_SURFACE):
                s = stats[klass]
                cells.append(s.interval().render() if s.events else "n/a")
            print(f"| {engine_name} | {cells[0]} | {cells[1]} |")
        if result["departures"]:
            ranked = sorted(result["departures"].items(), key=lambda kv: -kv[1])
            print("\nFields that left the surface: "
                  + ", ".join(f"{k} ({v})" for k, v in ranked))
        report[name] = {
            "mix": result["mix"],
            "departures": result["departures"],
            "containment": {
                e: {k: round(result["per_engine"][e][k].rate, 4)
                    for k in (SURFACE_LEAVING, IN_SURFACE)}
                for e in engine_names
            },
        }

    print("\n## Reading\n")
    print("A headline containment number is a weighted average over this mix, and every "
          "corpus here picks its own weights. Quoting one number across corpora with "
          "different mixes compares nothing. The defensible claim is per class: "
          "authorization contains what leaves the surface, and does not decide what stays "
          "inside it. The in-surface column is where aggregate limits (budgets, rates) and "
          "the behavioral layer have to do the work, and where an honest evaluation should "
          "concentrate rather than adding more surface-leaving corpora.")

    if args.json:
        args.json.write_text(json.dumps(report, indent=2))
        print(f"\nWrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
