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
from benchmarks.core.leaderboard import (
    render_markdown,
    render_multiseed_markdown,
    run_leaderboard,
    run_leaderboard_multiseed,
)
from benchmarks.datasets.base import get_loader


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Adversarial enforcement leaderboard")
    p.add_argument("--dataset", default="fixture")
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--engines", default=None, help="comma-separated engine names")
    p.add_argument("--classes", default=None, help="comma-separated attack classes")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--seeds", default=None,
                   help="run several synthesis seeds and report the spread, e.g. '0-9' or '0,1,2'")
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    try:
        tasks = get_loader(args.dataset).load(limit=args.limit)
    except (KeyError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    engines = build_engines([n.strip() for n in args.engines.split(",")]) if args.engines else None
    classes = [c.strip() for c in args.classes.split(",")] if args.classes else list(ATTACK_CLASSES)
    print(f"# Adversarial leaderboard — {args.dataset} "
          f"({len(tasks)} benign tasks x {len(classes)} attack classes)\n")

    if args.seeds:
        seeds = _parse_seeds(args.seeds)
        spreads = run_leaderboard_multiseed(tasks, engines=engines, classes=classes, seeds=seeds)
        print(render_multiseed_markdown(spreads, classes, seeds))
        return 0

    boards = run_leaderboard(tasks, engines=engines, classes=classes, seed=args.seed)
    print(render_markdown(boards, classes))
    return 0


def _parse_seeds(spec: str) -> list[int]:
    """Accepts '0-9', '0,3,7', or a mix of both."""
    seeds: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            seeds.extend(range(int(lo), int(hi) + 1))
        elif part:
            seeds.append(int(part))
    if not seeds:
        raise ValueError(f"no seeds parsed from {spec!r}")
    return seeds


if __name__ == "__main__":
    raise SystemExit(main())
