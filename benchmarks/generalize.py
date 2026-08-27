"""The generalisation curve: what a pattern mandate buys, and where it collapses.

    python -m benchmarks.generalize            # single-knob curve, every corpus
    python -m benchmarks.generalize --typed    # tool and path dimensions separated

Runs the full scoreboard at each generalisation LEVEL and prints containment and
both false-block columns side by side, because the gain and the loss are the same
mechanism seen from two sides. A level that recovers friction on tau2 by covering
benign work it did not observe covers attacks it did not observe by the same rule.

Level 0 must reproduce the shipped numbers exactly. It is checked, not assumed:
``--check`` fails loudly if it does not, which is the only guard against a sweep
that silently re-measures something other than the system.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from benchmarks.core.engines import build_engines
from benchmarks.core.events import EventLabel
from benchmarks.core.heldout import circular_unsplittable, hold_out_corpus
from benchmarks.core.patterns import LEVELS, generalize_corpus
from benchmarks.core.runner import run_benchmark
from benchmarks.datasets.base import get_loader

# Match scoreboard.DEPLOYABLE, velocity is an ablation, not the product top.
DEPLOYABLE = [
    "tool-allowlist",
    "capability-token",
    "task-scope",
    "task-scope+binding",
    "task-scope+binding+budget",
]
TOP = DEPLOYABLE[-1]

CONTAINMENT = ["redcode", "asb", "ipi_coding", "agent_threat_bench",
               "injecagent", "toolemu", "agentharm", "sleight"]
FRICTION = ["tau2", "bfcl", "atif"]
ALL = ["redcode", "asb", "ipi_coding", "agent_threat_bench", "injecagent",
       "toolemu", "agentharm", "sleight", "tau2", "bfcl", "atif"]


def _load(name: str):
    return list(get_loader(name).load())


def measure(tasks, *, tool_level: int, path_level: int, verb_level: int = 0,
            seed: int = 0, paths_from_traffic: bool = False,
            check_ladder: bool = False) -> dict:
    """One corpus at one operating point: containment, FB(granted), FB(held out)."""
    granted = generalize_corpus(tasks, tool_level=tool_level, path_level=path_level,
                                verb_level=verb_level, seed=seed,
                                paths_from_traffic=paths_from_traffic)
    engines = [e for e in build_engines() if e.name in DEPLOYABLE]
    res = run_benchmark(granted, engines)[TOP]
    unscoreable = any(t.meta.get("false_block_unscoreable") for t in tasks)

    held_tasks, corrected = hold_out_corpus(
        tasks, seed=seed, tool_level=tool_level, path_level=path_level,
        verb_level=verb_level)
    if not corrected and circular_unsplittable(tasks):
        unscoreable = True
    heldout = None
    if corrected:
        hr = run_benchmark(
            held_tasks, [e for e in build_engines() if e.name in DEPLOYABLE])[TOP]
        heldout = hr.false_block_rate

    # Ladder monotonicity AT THIS LEVEL, per event: a pattern grant must not let
    # a lower rung contain an attack the top rung allows.
    rung = None
    if check_ladder:
        ladder = run_benchmark(granted,
                               [e for e in build_engines() if e.name in DEPLOYABLE],
                               calibration_seed=None)
        rung = {k: (v.attack_prevention_rate if v.n_attack else None)
                for k, v in ladder.items()}
    return {
        "contained": res.attack_prevention_rate if res.n_attack else None,
        "fb_granted": None if unscoreable else res.false_block_rate,
        "fb_heldout": heldout,
        "n_attack": res.n_attack,
        "n_benign": res.n_benign,
        "rung_contained": rung,
    }


def _fmt(x, pct=True):
    if x is None:
        return "-"
    return f"{100 * x:.2f}%" if pct else f"{x}"


def resource_dimension_is_independent(tasks) -> bool:
    """Does this corpus name resources as something other than its tools?

    `patterns.generalize_task` routes BOTH the tool and the resource dimension
    off `tool_level`, justified in its docstring by "they are 1:1 in every
    loader that names resources `mcp:tool:<tool>`". That condition is stated and
    never checked, and it is false for 8 of the 18 corpora in the registry:
    agent_threat_bench, agentharm, agentleak, b3, ipi_coding, mind2web_sc,
    redcode and sleight all name resources on an axis of their own.

    Where it is false, `--typed tool` silently varies the resource dimension too,
    so a result read off that column as a fact about TOOL patterns may be a fact
    about resource patterns instead.

    Mind2Web-SC is the case that proves it matters. Its tools are `click`,
    `select` and `type`, granted identically in every task, so the tool dimension
    cannot carry any signal at all; its containment is entirely `web:car` vs
    `web:media`. It reads as 98% to 0% under a `tool+verb` sweep. Generalise the
    tools and verbs while pinning resources and it is **98.0%, unchanged**.
    """
    events = [e for t in tasks for e in t.events][:400]
    if not events:
        return False
    matched = sum(1 for e in events if e.resource == f"mcp:tool:{e.tool_name}")
    return matched / len(events) < 0.99


def sweep(corpora, levels, *, seed: int = 0, paths_from_traffic: bool = False,
          typed: str | None = None, check_ladder: bool = False) -> dict:
    """``typed`` = 'tool' | 'path' | 'verb' varies one dimension, pinning the rest."""
    cache = {}
    out: dict = {}
    for name in corpora:
        try:
            cache[name] = _load(name)
        except Exception as exc:  # corpus not fetched
            out[name] = {"error": str(exc)[:120]}
            continue
        rows = {}
        confounded = (typed in ("tool", "tool+verb")
                      and resource_dimension_is_independent(cache[name]))
        for lvl in levels:
            tl = lvl if typed in (None, "tool", "tool+verb", "all") else 0
            pl = lvl if typed in (None, "path", "all") else 0
            vl = lvl if typed in ("verb", "tool+verb", "all") else 0
            rows[LEVELS[lvl]] = measure(
                cache[name], tool_level=tl, path_level=pl, verb_level=vl,
                seed=seed, paths_from_traffic=paths_from_traffic,
                check_ladder=check_ladder)
        out[name] = rows
        if confounded:
            out[name]["_confounded"] = True
    return out


def render(results: dict, levels, title: str) -> str:
    lines = [title, "=" * len(title), ""]
    head = f"{'corpus':<20}{'level':<12}{'contained':>11}{'FB(granted)':>13}{'FB(held out)':>14}"
    lines.append(head)
    lines.append("-" * len(head))
    for name, rows in results.items():
        if "error" in rows:
            lines.append(f"{name:<20}{'corpus not fetched':<12}")
            continue
        for lvl in levels:
            r = rows[LEVELS[lvl]]
            lines.append(
                f"{name:<20}{LEVELS[lvl]:<12}"
                f"{_fmt(r['contained']):>11}{_fmt(r['fb_granted']):>13}"
                f"{_fmt(r['fb_heldout']):>14}"
            )
        if rows.get("_confounded"):
            lines.append(
                f"{'':<20}^ CONFOUNDED: this corpus names resources on an axis of "
                f"its own, and\n{'':<20}  tool_level drives the resource dimension "
                f"too, so these rows are\n{'':<20}  NOT a tool-dimension result. "
                f"See resource_dimension_is_independent.")
        lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--corpora", nargs="*", default=ALL)
    p.add_argument("--levels", nargs="*", type=int, default=[0, 1, 2, 3, 4])
    p.add_argument("--typed",
                   choices=["tool", "path", "verb", "tool+verb", "all"],
                   default=None)
    p.add_argument("--check-ladder", action="store_true")
    p.add_argument("--paths-from-traffic", action="store_true")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--json", type=Path, default=None)
    args = p.parse_args(argv)

    res = sweep(args.corpora, args.levels, seed=args.seed,
                paths_from_traffic=args.paths_from_traffic, typed=args.typed,
                check_ladder=args.check_ladder)
    title = ("generalisation curve"
             + (f" [{args.typed} dimension only]" if args.typed else "")
             + (" [path scope rebuilt from clean traffic]" if args.paths_from_traffic else "")
             + f" [seed {args.seed}]")
    print(render(res, args.levels, title))
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(res, indent=2))
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
