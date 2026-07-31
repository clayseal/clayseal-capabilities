"""CLI: per-attack-class enforcement leaderboard over synthesized adversarial data.

    python -m benchmarks.leaderboard --dataset agentdojo --limit 500
    python -m benchmarks.leaderboard --dataset fixture --seed 1

Loads a dataset's benign tasks, synthesizes attack variants across the taxonomy,
and prints containment per attack class for every enforcement engine.
"""
from __future__ import annotations

import argparse
import sys

from benchmarks.adversarial.attacks import ATTACK_CLASSES
from benchmarks.core.engines import build_engines
from benchmarks.core.leaderboard import render_markdown, run_leaderboard
from benchmarks.datasets.base import get_loader


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Adversarial enforcement leaderboard")
    p.add_argument("--dataset", default="fixture")
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--engines", default=None, help="comma-separated engine names")
    p.add_argument("--classes", default=None, help="comma-separated attack classes")
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    try:
        tasks = get_loader(args.dataset).load(limit=args.limit)
    except (KeyError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    engines = build_engines([n.strip() for n in args.engines.split(",")]) if args.engines else None
    classes = [c.strip() for c in args.classes.split(",")] if args.classes else list(ATTACK_CLASSES)
    boards = run_leaderboard(tasks, engines=engines, classes=classes, seed=args.seed)
    print(f"# Adversarial leaderboard — {args.dataset} "
          f"({len(tasks)} benign tasks x {len(classes)} attack classes)\n")
    print(render_markdown(boards, classes))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
