"""The load-bearing test: does a density rung flatten the generalization cliff?

    python -m benchmarks.density_sweep
    python -m benchmarks.density_sweep --corpora redcode --seeds 0 1 2

`benchmarks/generalize.py` established the defect. Holding every other dimension
fixed and wildcarding the PATH grant by one segment:

    redcode              99.86% -> 33.29% contained
    ipi_coding          100.00% -> 30.00%
    agent_threat_bench  100.00% ->  0.00%

while generalizing the TOOL dimension costs nothing. So the flagship containment
is a single mechanism — the attack path is outside a literally enumerated set —
and it does not survive the grant being written the way an operator writes one.

The thesis is that a goal-conditioned density over resource identity is a second,
independent signal that survives grant generalization, because it discriminates
by *how often the cohort goes there* rather than by membership. This module tests
it directly: the same sweep, with and without the density rung, at each
generalization level.

What would falsify it: containment at `up1`/`up2` staying flat when the rung is
added, or rising only by paying a false-block rate far above the rung's declared
`alpha`. Both columns are printed side by side for exactly that reason. A rung
that buys containment with friction has not solved the problem, it has moved
along the same frontier — which is what every rung below it already does.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

from benchmarks.core.engines import build_engines
from benchmarks.core.patterns import LEVELS, generalize_corpus
from benchmarks.core.runner import run_benchmark
from benchmarks.datasets.base import get_loader

BASE = "task-scope+binding+budget+velocity"
DENSITY = "task-scope+binding+budget+velocity+density"

# Corpora where the cliff was measured: path-defined attacks with a real attack
# count. Content-defined corpora (agentharm, sleight) are excluded because the
# density channel scores ~chance on them by construction, which opeval.md already
# reports; including them here would dilute the test with cases the mechanism
# openly does not address.
DEFAULT_CORPORA = ["redcode", "ipi_coding", "agent_threat_bench"]


def measure(tasks, *, engine_name: str, path_level: int, seed: int) -> dict:
    """One corpus, one engine, one generalization level."""
    granted = generalize_corpus(tasks, tool_level=0, path_level=path_level,
                                verb_level=0, seed=seed)
    engine = build_engines([engine_name])[0]
    result = run_benchmark(granted, [engine], calibration_seed=seed)[engine_name]
    return {
        "contained": result.attack_prevention_rate if result.n_attack else None,
        "false_block": result.false_block_rate,
        "n_attack": result.n_attack,
        "n_benign": result.n_benign,
    }


def sweep(corpora, levels, seeds) -> dict:
    out: dict = {}
    for name in corpora:
        try:
            tasks = list(get_loader(name).load())
        except Exception as exc:
            out[name] = {"error": str(exc)[:120]}
            continue
        rows: dict = {}
        for level in levels:
            cell: dict = {}
            for engine_name, key in ((BASE, "base"), (DENSITY, "density")):
                runs = [measure(tasks, engine_name=engine_name,
                                path_level=level, seed=s) for s in seeds]
                contained = [r["contained"] for r in runs if r["contained"] is not None]
                fb = [r["false_block"] for r in runs]
                cell[key] = {
                    "contained": statistics.mean(contained) if contained else None,
                    "contained_sd": (statistics.stdev(contained)
                                     if len(contained) > 1 else 0.0),
                    "false_block": statistics.mean(fb) if fb else None,
                    "false_block_sd": statistics.stdev(fb) if len(fb) > 1 else 0.0,
                    "n_attack": runs[0]["n_attack"],
                    "n_benign": runs[0]["n_benign"],
                }
            rows[LEVELS[level]] = cell
        out[name] = rows
    return out


def _pct(x, sd=None):
    if x is None:
        return "-"
    base = f"{100 * x:.2f}%"
    if sd:
        base += f"±{100 * sd:.1f}"
    return base


def render(results: dict, levels, seeds) -> str:
    head = (f"{'corpus':<20}{'level':<11}"
            f"{'contained':>12}{'+density':>14}{'delta':>10}"
            f"{'FB':>10}{'FB+density':>13}")
    lines = [
        f"density rung vs the ladder it sits on [{len(seeds)} seeds: "
        f"{', '.join(map(str, seeds))}]",
        "=" * len(head), "", head, "-" * len(head),
    ]
    for name, rows in results.items():
        if "error" in rows:
            lines.append(f"{name:<20}corpus not available")
            continue
        for level in levels:
            cell = rows[LEVELS[level]]
            b, d = cell["base"], cell["density"]
            delta = ("-" if b["contained"] is None or d["contained"] is None
                     else f"{100 * (d['contained'] - b['contained']):+.1f}")
            lines.append(
                f"{name:<20}{LEVELS[level]:<11}"
                f"{_pct(b['contained']):>12}"
                f"{_pct(d['contained'], d['contained_sd']):>14}"
                f"{delta:>10}"
                f"{_pct(b['false_block']):>10}"
                f"{_pct(d['false_block'], d['false_block_sd']):>13}"
            )
        lines.append("")
    lines.append("The density rung declares alpha=0.01. Read the two FB columns "
                 "together with")
    lines.append("the delta: containment bought at an FB far above alpha is not "
                 "a win, it is")
    lines.append("the same frontier every rung below already sits on.")
    return "\n".join(lines)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--corpora", nargs="*", default=DEFAULT_CORPORA)
    p.add_argument("--levels", nargs="*", type=int, default=[0, 1, 2, 3])
    p.add_argument("--seeds", nargs="*", type=int, default=[0, 1, 2])
    p.add_argument("--json", type=Path, default=None)
    args = p.parse_args(argv)

    results = sweep(args.corpora, args.levels, args.seeds)
    print(render(results, args.levels, args.seeds))
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(results, indent=2))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
