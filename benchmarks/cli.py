"""Command-line entry point for the capability-enforcement benchmark.

    python -m benchmarks.cli --dataset fixture
    python -m benchmarks.cli --dataset agentdojo --limit 200 --json out.json
    python -m benchmarks.cli --dataset fixture --engines allow-all,capability-token,task-scope+binding
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from benchmarks.core.engines import CONTROLS, LADDER, build_engines
from benchmarks.core.report import render_json, render_markdown
from benchmarks.core.runner import run_benchmark
from benchmarks.datasets.base import available_datasets, get_loader


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Clay Seal enforcement benchmark")
    parser.add_argument("--dataset", default="fixture",
                        help=f"one of: {', '.join(available_datasets())}")
    parser.add_argument("--engines", default=",".join(LADDER + CONTROLS),
                        help="comma-separated engine names (see benchmarks/README.md). Defaults to the ladder plus the controls, because a containment number that does not beat its controls is not a measurement.")
    parser.add_argument("--limit", type=int, default=None,
                        help="max tasks to load")
    parser.add_argument("--data-root", default=None,
                        help="corpus path for datasets that need one (injecagent, toolemu)")
    parser.add_argument("--json", type=Path, default=None,
                        help="also write full results as JSON to this path")
    parser.add_argument("--title", default="Clay Seal enforcement benchmark")
    parser.add_argument(
        "--mode", choices=["stack", "ladder", "detector"], default="stack",
        help="'stack' = DeployableStack product gateway (default); "
             "'ladder' = monotone floor ablation; "
             "'detector' = trajectory-level behavioral layer",
    )
    parser.add_argument(
        "--no-entailment", action="store_true",
        help="stack mode: disable LLM entailment (det soft content still on)",
    )
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
    print(f"# Trajectory detector, {args.dataset} (scorer={result.scorer}, alpha={result.alpha})")
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


def _corpus_caveats(tasks, engines) -> list[str]:
    """What the corpus and the engines already know about their own numbers.

    Three facts were being recorded and thrown away. A loader can declare that a
    rung is invalid for its corpus (`ladder_rung`) and that its false-block
    column is not a measurement (`false_block_unscoreable`); `scoreboard.py`
    reads both and this path, the one every `benchmarks/results/new-suites/*.md`
    is generated by, read neither. And a rung that calibrates can silently fall
    back to a constant when the corpus gives it nothing to calibrate on.

    So `sleight.md` published a velocity row at 65.9% containment / 16.1%
    false-block, from a cap that was never calibrated, on a corpus whose own
    loader says velocity "misreads long coding-agent sessions as abuse" and whose
    false-block column it marks unscoreable. Every part of that was already
    written down somewhere in this repository. None of it reached the table.
    """
    lines: list[str] = []
    rung = next((t.meta.get("ladder_rung") for t in tasks
                 if t.meta.get("ladder_rung")), None)
    names = [e.name for e in engines]
    if rung and rung in names:
        beyond = names[names.index(rung) + 1:]
        beyond = [n for n in beyond if n not in ("deny-all", "position-only-control")]
        if beyond:
            lines.append(
                f"\n> **This corpus declares its highest valid rung as `{rung}`.** "
                f"Rows above it ({', '.join(beyond)}) are printed for ablation and "
                f"are not results for this corpus.")
    if any(t.meta.get("false_block_unscoreable") for t in tasks):
        lines.append(
            "\n> **The false-block column is not scoreable on this corpus.** The "
            "mandate is derived from the benign twin, so that twin is clean by "
            "construction. Friction is measured on corpora that do not have this "
            "property.")
    uncal = [e.name for e in engines
             if hasattr(e, "calibrated") and not e.calibrated]
    if uncal:
        lines.append(
            f"\n> **Uncalibrated:** {', '.join(uncal)} found no attack-free task to "
            f"calibrate on and fell back to a built-in constant. The row is that "
            f"constant's behaviour, not a limit learned from this corpus's traffic.")
    if "position-only-control" in names:
        lines.append(
            "\n> `position-only-control` reads nothing but an event's index in its "
            "task. It is a floor, not a defense: a rung that does not beat it is "
            "reporting the order of the corpus rather than the content of the "
            "actions.")
    return lines


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

    if args.mode == "stack":
        return _run_stack(args, tasks)

    engines = build_engines([n.strip() for n in args.engines.split(",") if n.strip()])
    results = run_benchmark(tasks, engines)

    n_benign = sum(t.counts()[0] for t in tasks)
    n_attack = sum(t.counts()[1] for t in tasks)
    title = (
        f"{args.title}, {args.dataset} ladder ablation "
        f"({len(tasks)} tasks, {n_benign} benign / {n_attack} attack events)"
    )
    print(render_markdown(results, title=title, ci=args.ci, level=args.level))
    for line in _corpus_caveats(tasks, engines):
        print(line)

    if args.json:
        args.json.write_text(render_json(results))
        print(f"\nWrote JSON results to {args.json}", file=sys.stderr)
    return 0


def _run_stack(args, tasks) -> int:
    """Product path: one DeployableStack profile (hard/soft split)."""
    import json as _json

    from benchmarks.core.broker_eval import run_broker_benchmark

    judge = None
    if not args.no_entailment:
        judge = ...  # DeployableStack / broker_eval default judge
    result = run_broker_benchmark(tasks, entailment_judge=judge)
    n_benign = sum(t.counts()[0] for t in tasks)
    n_attack = sum(t.counts()[1] for t in tasks)
    print(
        f"# DeployableStack, {args.dataset} "
        f"({len(tasks)} tasks, {n_benign} benign / {n_attack} attack events)"
    )
    print(
        f"union {result.attack_prevention_rate:.1%} | "
        f"hard {result.hard_attack_prevention_rate:.1%} | "
        f"soft {result.soft_attack_prevention_rate:.1%} | "
        f"FB {result.false_block_rate:.1%} "
        f"(h {result.hard_false_block_rate:.1%} / s {result.soft_false_block_rate:.1%})"
    )
    print(
        "Never quote soft as hard ASR. Ladder ablation: "
        "`--mode ladder`."
    )
    if args.json:
        payload = {
            "profile": "deployable-stack",
            "dataset": args.dataset,
            "n_tasks": len(tasks),
            "n_attack": result.n_attack,
            "n_benign": result.n_benign,
            "union": result.attack_prevention_rate,
            "hard": result.hard_attack_prevention_rate,
            "soft": result.soft_attack_prevention_rate,
            "false_block": result.false_block_rate,
            "hard_false_block": result.hard_false_block_rate,
            "soft_false_block": result.soft_false_block_rate,
        }
        args.json.write_text(_json.dumps(payload, indent=2))
        print(f"\nWrote JSON results to {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
