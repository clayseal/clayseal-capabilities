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
    the one an operator would set — which inflates containment. The density rung
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


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Adaptive red-team benchmark")
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

    print(f"# Adaptive red-team — {args.dataset} ({len(tasks)} tasks, "
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
