"""Command-line entry point for the capability-enforcement benchmark.

    python -m benchmarks.cli --dataset fixture
    python -m benchmarks.cli --dataset agentdojo --limit 200 --json out.json
    python -m benchmarks.cli --dataset fixture --engines allow-all,capability-token,task-scope+binding
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from benchmarks.core.engines import LADDER, build_engines
from benchmarks.core.report import render_json, render_markdown
from benchmarks.core.runner import run_benchmark
from benchmarks.datasets.base import available_datasets, get_loader


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Clay Seal enforcement benchmark")
    parser.add_argument("--dataset", default="fixture",
                        help=f"one of: {', '.join(available_datasets())}")
    parser.add_argument("--engines", default=",".join(LADDER),
                        help="comma-separated engine names (see benchmarks/README.md)")
    parser.add_argument("--limit", type=int, default=None,
                        help="max tasks to load")
    parser.add_argument("--data-root", default=None,
                        help="corpus path for datasets that need one (injecagent, toolemu)")
    parser.add_argument("--json", type=Path, default=None,
                        help="also write full results as JSON to this path")
    parser.add_argument("--title", default="Clay Seal enforcement benchmark")
    parser.add_argument("--mode", choices=["ladder", "detector"], default="ladder",
                        help="'ladder' = per-action engines; 'detector' = trajectory-level behavioral layer")
    parser.add_argument("--scorer", choices=["ngram", "transformer"], default="ngram",
                        help="detector mode: sequence scorer")
    parser.add_argument("--model-dir", type=Path, default=None,
                        help="detector mode: trained transformer checkpoint dir")
    parser.add_argument("--ci", action="store_true",
                        help="report task-clustered bootstrap confidence intervals on every rate")
    parser.add_argument("--level", type=float, default=0.95,
                        help="confidence level for --ci")
    parser.add_argument("--alpha", type=float, default=0.05,
                        help="detector mode: conformal false-alarm budget")
    return parser.parse_args(argv)


def _run_detector(args, tasks) -> int:
    import json as _json

    from agentauth.capabilities.monitor import NGramScorer, TrajectoryDetector
    from benchmarks.core.detector_eval import run_detector_benchmark

    if args.scorer == "transformer":
        from agentauth.capabilities.monitor.scoring.transformer import TransformerScorer

        if not args.model_dir:
            print("error: --scorer transformer needs --model-dir", file=sys.stderr)
            return 2
        scorer = TransformerScorer.load(args.model_dir)
    else:
        scorer = NGramScorer()
    detector = TrajectoryDetector(scorer=scorer, alpha=args.alpha)
    result = run_detector_benchmark(tasks, detector=detector)
    print(f"# Trajectory detector — {args.dataset} (scorer={result.scorer}, alpha={result.alpha})")
    print(f"containment {result.containment_rate:.1%} | "
          f"false-block {result.false_block_rate:.1%} | "
          f"train {result.n_train} / test {result.n_test} / attacks {result.attack_trajectories}")
    if args.json:
        args.json.write_text(_json.dumps(result.summary(), indent=2))
    return 0


def _loader_with_data_root(dataset: str, data_root: str | None):
    """Build a loader, threading ``--data-root`` into the ones that accept it."""
    if data_root and dataset == "injecagent":
        from benchmarks.datasets.injecagent import InjecAgentLoader

        return InjecAgentLoader(data_root=data_root)
    if data_root and dataset == "toolemu":
        from benchmarks.datasets.toolemu import ToolEmuLoader

        return ToolEmuLoader(data_root=data_root)
    if data_root and dataset == "redcode":
        from benchmarks.datasets.redcode import RedCodeLoader

        return RedCodeLoader(data_root=data_root)
    if data_root and dataset == "agentharm":
        from benchmarks.datasets.agentharm import AgentHarmLoader

        return AgentHarmLoader(data_root=data_root)
    if data_root and dataset == "asb":
        from benchmarks.datasets.asb import AsbLoader

        return AsbLoader(data_root=data_root)
    return get_loader(dataset)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    try:
        loader = _loader_with_data_root(args.dataset, args.data_root)
        tasks = loader.load(limit=args.limit)
    except (KeyError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not tasks:
        print("error: dataset produced no tasks", file=sys.stderr)
        return 2

    if args.mode == "detector":
        return _run_detector(args, tasks)

    engines = build_engines([n.strip() for n in args.engines.split(",") if n.strip()])
    results = run_benchmark(tasks, engines)

    n_benign = sum(t.counts()[0] for t in tasks)
    n_attack = sum(t.counts()[1] for t in tasks)
    title = f"{args.title} — {args.dataset} ({len(tasks)} tasks, {n_benign} benign / {n_attack} attack events)"
    print(render_markdown(results, title=title, ci=args.ci, level=args.level))

    if args.json:
        args.json.write_text(render_json(results))
        print(f"\nWrote JSON results to {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
