"""CLI: enforcement latency distribution per ladder rung.

    python -m benchmarks.latency --dataset redcode --repeats 20

A buyer's second question, right after "what does it catch", is "what does it
cost me". Answering with a mean is not an answer: authorization sits in the
critical path of every tool call, so the number that determines whether an agent
feels slow is the tail, not the average. This reports p50/p95/p99/max and the
cost *increment* each rung adds over the one below.

Deliberately measured without the replay loop's bookkeeping around it, with a
warm-up pass so the first-call scope compilation and its cache do not land in
the sample. Scope compilation is amortized per task in production exactly as it
is here, so warming it is the honest choice rather than a flattering one; the
cold-start cost is reported separately instead of being hidden.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

from benchmarks.core.engines import LADDER, build_engines
from benchmarks.datasets.base import get_loader


def _percentile(ordered: list[float], q: float) -> float:
    if not ordered:
        return 0.0
    idx = min(int(len(ordered) * q), len(ordered) - 1)
    return ordered[idx]


def measure(engine, tasks, repeats: int) -> dict:
    pairs = [(t, e) for t in tasks for e in t.events]

    # Warm-up: compile scopes, populate caches, let the JIT-free interpreter
    # settle. Excluded from the sample and reported on its own below.
    cold_start = time.perf_counter()
    for task, event in pairs:
        engine.decide(task, event)
    cold_ms = (time.perf_counter() - cold_start) * 1000.0

    samples: list[float] = []
    for _ in range(repeats):
        for task, event in pairs:
            start = time.perf_counter_ns()
            engine.decide(task, event)
            samples.append((time.perf_counter_ns() - start) / 1000.0)  # microseconds

    samples.sort()
    return {
        "engine": engine.name,
        "decisions": len(samples),
        "p50_us": round(_percentile(samples, 0.50), 3),
        "p95_us": round(_percentile(samples, 0.95), 3),
        "p99_us": round(_percentile(samples, 0.99), 3),
        "max_us": round(samples[-1], 3) if samples else 0.0,
        "mean_us": round(statistics.fmean(samples), 3) if samples else 0.0,
        "cold_pass_ms": round(cold_ms, 3),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Enforcement latency benchmark")
    p.add_argument("--dataset", default="redcode")
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--repeats", type=int, default=20)
    p.add_argument("--engines", default=",".join(LADDER))
    p.add_argument("--json", type=Path, default=None)
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    try:
        tasks = get_loader(args.dataset).load(limit=args.limit)
    except (KeyError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    rows = [measure(engine, tasks, args.repeats)
            for engine in build_engines([n.strip() for n in args.engines.split(",") if n.strip()])]

    n = rows[0]["decisions"] if rows else 0
    print(f"# Enforcement latency, {args.dataset} ({len(tasks)} tasks, {n} decisions per engine)\n")
    header = ["Engine", "p50 (us)", "p95 (us)", "p99 (us)", "max (us)", "added over previous"]
    print("| " + " | ".join(header) + " |")
    print("| " + " | ".join("---" for _ in header) + " |")
    previous = None
    for row in rows:
        delta = "-" if previous is None else f"{row['p50_us'] - previous:+.3f} us"
        previous = row["p50_us"]
        print(f"| {row['engine']} | {row['p50_us']:.3f} | {row['p95_us']:.3f} | "
              f"{row['p99_us']:.3f} | {row['max_us']:.3f} | {delta} |")

    full = next((r for r in rows if r["engine"] == "task-scope+binding+budget"), None)
    if full:
        print(
            f"\nThe full stack decides in {full['p50_us']:.1f} us at p50 and "
            f"{full['p99_us']:.1f} us at p99. For scale, a single LLM tool-call round trip is "
            "on the order of hundreds of milliseconds, so enforcement is roughly four orders of "
            "magnitude below the thing it gates and is not a throughput consideration for an "
            "agent. It would be one for an inline syscall filter, which is why the syscall-"
            "boundary layer is measured separately rather than extrapolated from these numbers."
        )
        print(
            f"\nCold pass (scope compilation, cache population) over all {len(tasks)} tasks: "
            f"{full['cold_pass_ms']:.1f} ms, amortized once per task and excluded from the "
            "distribution above."
        )

    if args.json:
        args.json.write_text(json.dumps(rows, indent=2))
        print(f"\nWrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
