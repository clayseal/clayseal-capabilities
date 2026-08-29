"""CLI: iterated adaptive red-team against the enforcement ladder.

    python -m benchmarks.adaptive --dataset redcode --rounds 5
    python -m benchmarks.adaptive --dataset fixture --objective persistence --json out.json

Reports containment as a function of attacker knowledge (blind / feedback /
oracle) rather than a single number against a fixed corpus. See
benchmarks/adversarial/adaptive.py for why the objective predicate, not the
engine's verdict, decides what counts as an escape.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from benchmarks.adversarial.adaptive import (
    OBJECTIVES,
    Knowledge,
    render_markdown,
    run_adaptive,
)
from benchmarks.core.engines import LADDER, build_engines
from benchmarks.core.runner import _calibration_split
from benchmarks.datasets.base import get_loader


def calibrate(engines, tasks, seed: int = 0):
    """Give calibrated engines their one look at clean traffic before the attack.

    ``run_benchmark`` does this through ``observe_corpus``; this path did not, and
    the omission is not cosmetic. Uncalibrated, ``VelocityLadderEngine`` falls
    back to ``default_cap = 5`` while calibration on RedCode yields **32**, so
    every adaptive result for that rung was produced with a cap 6.4x tighter than
    the one an operator would set, which inflates containment. The density rung
    is worse off: with no baseline it abstains entirely, so its row was a copy of
    its parent's.

    The split is the runner's own: half the CLEAN tasks calibrate, attack-bearing
    tasks never do, so no engine sees the task it is about to be attacked on.
    """
    calibration, _ = _calibration_split(list(tasks), seed)
    for engine in engines:
        observe = getattr(engine, "observe_corpus", None)
        if observe is not None:
            observe(calibration)
    return engines


#: The grid `--sweep` runs. Four corpora and six objectives, chosen so the table
#: contains both outcomes. The first four objectives name a destination or a
#: path the gateway can bind to; the last two keep the whole attack inside the
#: grant, which is the case nothing here closes. A sweep that showed only the
#: first four would be a sweep picked to win.
SWEEP_DATASETS = ("redcode", "agentharm", "mcp_attack", "ipi_coding")
SWEEP_OBJECTIVES = ("destruction", "exfiltration", "persistence", "side-channel",
                    "in-scope-exfiltration", "in-scope-content-staging")


def _sweep(args) -> int:
    """The whole grid under one command, so the published table has a source.

    The per-run CLI below answers one cell. A result file quoting a table of
    them had no command that produced the table, which is how
    `adaptive_adversary.md` ended up stamped `unverified`: the numbers were
    real and nobody could re-derive them.
    """
    from benchmarks.core.reporting import format_rate
    from benchmarks.core.runner import run_benchmark

    rows: list[dict] = []
    cost: dict[str, tuple[int, int]] = {}
    for dataset in [d.strip() for d in args.datasets.split(",") if d.strip()]:
        try:
            tasks = get_loader(dataset).load(limit=args.limit)
        except (KeyError, RuntimeError) as exc:
            print(f"# {dataset}: not fetched ({exc})", file=sys.stderr)
            continue
        if not tasks:
            continue

        # The cost of the same arm, on the same tasks. `check_claims` refuses a
        # containment figure published without one, and it is right to: deny-all
        # contains everything. This replays the benign side through the same
        # ladder the attack rows are scored on.
        benign_engines = build_engines(
            [n.strip() for n in args.engines.split(",") if n.strip()])
        scored = run_benchmark(tasks, benign_engines, calibration_seed=args.seed)
        full_result = scored.get("task-scope+binding+budget+velocity")
        if full_result is not None:
            cost[dataset] = (full_result.benign_blocked, full_result.n_benign)

        for objective_name in [o.strip() for o in args.objectives.split(",") if o.strip()]:
            objective = OBJECTIVES[objective_name]()
            engines = build_engines(
                [n.strip() for n in args.engines.split(",") if n.strip()])
            calibrate(engines, tasks, seed=args.seed)
            for engine in engines:
                for level in [Knowledge(k.strip())
                              for k in args.knowledge.split(",") if k.strip()]:
                    result = run_adaptive(
                        tasks, engine, objective=objective, knowledge=level,
                        rounds=args.rounds, seed=args.seed, breadth=args.breadth,
                    )
                    rows.append({"dataset": dataset, "objective": objective_name,
                                 **result.summary()})

    if not rows:
        print("error: no corpus loaded; run benchmarks/fetch_corpora.sh",
              file=sys.stderr)
        return 2

    full = "task-scope+binding+budget+velocity"
    tried = sum(r["candidates_tried"] for r in rows)
    print(f"# Adaptive red-team sweep, {args.rounds} rounds, "
          f"{tried:,} candidates tried\n")
    print("Containment of the full stack against an attacker that knows the "
          "defense. `oracle` is the strongest case: the attacker sees each "
          "verdict and searches against it.\n")
    print("| corpus | objective | blind | feedback | oracle | allow-all, oracle |")
    print("| --- | --- | ---: | ---: | ---: | ---: |")
    for dataset in dict.fromkeys(r["dataset"] for r in rows):
        for objective_name in dict.fromkeys(
                r["objective"] for r in rows if r["dataset"] == dataset):
            def pick(engine, knowledge, *, ds=dataset, obj=objective_name):
                for r in rows:
                    if (r["dataset"] == ds and r["objective"] == obj
                            and r["engine"] == engine and r["knowledge"] == knowledge):
                        n = r["tasks_attacked"]
                        held = n - r["tasks_escaped"]
                        return format_rate(held, n)
                return "-"
            print(f"| {dataset} | {objective_name} "
                  f"| {pick(full, 'blind')} | {pick(full, 'feedback')} "
                  f"| {pick(full, 'oracle')} | {pick('allow-all', 'oracle')} |")

    print("\nWhat the same arm costs, on the benign side of the same corpora:\n")
    print("| corpus | benign events refused by the full stack |")
    print("| --- | ---: |")
    for dataset, (blocked, n) in cost.items():
        print(f"| {dataset} | {format_rate(blocked, n)} |")

    if args.json:
        args.json.write_text(json.dumps(rows, indent=2))
        print(f"\nWrote {args.json}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Adaptive red-team benchmark")
    p.add_argument("--sweep", action="store_true",
                   help="run the whole corpus x objective grid and print one table")
    p.add_argument("--datasets", default=",".join(SWEEP_DATASETS),
                   help="--sweep only")
    p.add_argument("--objectives", default=",".join(SWEEP_OBJECTIVES),
                   help="--sweep only")
    p.add_argument("--dataset", default="fixture")
    p.add_argument("--limit", type=int, default=100,
                   help="tasks to attack (the search is per-task, so this drives runtime)")
    p.add_argument("--engines", default=",".join(n for n in LADDER if n != "deny-all"))
    p.add_argument("--objective", default="exfiltration", choices=sorted(OBJECTIVES))
    p.add_argument("--rounds", type=int, default=5)
    p.add_argument("--breadth", type=int, default=12, help="candidates per round")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--knowledge", default="blind,feedback,oracle")
    p.add_argument("--json", type=Path, default=None)
    args = p.parse_args(argv if argv is not None else sys.argv[1:])
    if args.sweep:
        return _sweep(args)

    try:
        tasks = get_loader(args.dataset).load(limit=args.limit)
    except (KeyError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not tasks:
        print("error: dataset produced no tasks", file=sys.stderr)
        return 2

    objective = OBJECTIVES[args.objective]()
    engines = build_engines([n.strip() for n in args.engines.split(",") if n.strip()])
    calibrate(engines, tasks, seed=args.seed)
    levels = [Knowledge(k.strip()) for k in args.knowledge.split(",") if k.strip()]

    results = []
    for engine in engines:
        for level in levels:
            results.append(run_adaptive(
                tasks, engine, objective=objective, knowledge=level,
                rounds=args.rounds, seed=args.seed, breadth=args.breadth,
            ))

    print(f"# Adaptive red-team, {args.dataset} ({len(tasks)} tasks, "
          f"objective={objective.name}, {args.rounds} rounds)\n")
    print(f"_Objective: {objective.description}_ (ATT&CK {objective.attack_id})\n")
    print(render_markdown(results))

    surviving = [e for r in results for e in r.escapes]
    if surviving:
        print("\n## Surviving attacks\n")
        seen = set()
        for escape in surviving:
            key = (escape.engine, escape.knowledge, escape.strategy)
            if key in seen:
                continue
            seen.add(key)
            print(f"- **{escape.engine}** vs *{escape.knowledge}* attacker, "
                  f"round {escape.round_found}, `{escape.strategy}`: {escape.description}")
    else:
        print("\nNo attack achieved its objective against any engine at any knowledge level.")

    if args.json:
        args.json.write_text(json.dumps([r.summary() for r in results], indent=2))
        print(f"\nWrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
