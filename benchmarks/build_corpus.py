"""Build a benign-trajectory corpus (jsonl) for training the detector's scorer.

The detector is a one-class model: it learns "normal for this goal" from benign
trajectories only. This extracts the benign trajectory of every task in a
dataset and writes it in the corpus format the trainer reads.

    python -m benchmarks.build_corpus --dataset agentdojo --limit 2000 \
        --out benign.jsonl
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from benchmarks.core.detector_eval import task_to_trajectories
from benchmarks.datasets.base import get_loader
from clayseal.capabilities.monitor.training.data import dump_corpus


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build benign trajectory corpus")
    p.add_argument("--dataset", default="agentdojo")
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--data-root", default=None)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    try:
        if args.data_root and args.dataset in ("injecagent", "toolemu"):
            from benchmarks.cli import _loader_with_data_root

            loader = _loader_with_data_root(args.dataset, args.data_root)
        else:
            loader = get_loader(args.dataset)
        tasks = loader.load(limit=args.limit)
    except (KeyError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    benign = [b for b, _ in (task_to_trajectories(t) for t in tasks) if b.actions]
    if not benign:
        print("error: no benign trajectories produced", file=sys.stderr)
        return 2
    dump_corpus(benign, args.out)
    print(f"wrote {len(benign)} benign trajectories to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
