"""Repeat a live measurement and report the spread, not one draw from it.

    python -m benchmarks.live.repeat_runs --suite travel --repeats 3 \
        --ablations envelope-taint,envelope-taint-deferallow

Identical configuration on travel produced 50% and 75% autonomous utility on two
consecutive runs. At n=8 one task is 12.5 points, and the agent is stochastic, so
a single run cannot resolve any difference smaller than about 25 points. Several
comparisons already published sit inside that band.

This runs the same paired diagnostic several times and reports mean, spread, and
the per-run values, so a reader can see how much of a difference is real. It is
the cheapest possible fix for the problem: no new suites, no new models, just
the same measurement made more than once.

Aggregation is over TASKS rather than over run-level percentages: with the same
n per run the two agree, and pooling tasks keeps the interval meaningful if a
run dies partway.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from benchmarks.core.stats import proportion_ci
from benchmarks.live.summarize_ladder import summarize

PY = str(Path(__file__).resolve().parent.parent.parent / ".venv-h2h" / "bin" / "python")


def _env() -> dict:
    """Credentials for the child, resolved here rather than assumed.

    The first version inherited the caller's shell and every repeat failed with
    'Missing credentials', wasting three full runs before reporting it. A
    harness whose job is repetition should not depend on how it was invoked.
    Azure is explicitly cleared for the same reason the ladder driver clears it:
    `<aoai-resource>` is named gpt-4o-mini but serves gpt-5-mini.
    """
    import os

    env = dict(os.environ)
    if not env.get("OPENAI_API_KEY"):
        key_file = Path.home() / ".openai_api_key"
        if key_file.exists():
            env["OPENAI_API_KEY"] = key_file.read_text().strip()
    for var in ("AZURE_OPENAI_ENDPOINT", "AZURE_OPENAI_KEY", "AZURE_OPENAI_API_KEY"):
        env.pop(var, None)
    return env


def one_run(suite: str, model: str, n_user: int, ablations: str, out: Path) -> dict:
    cmd = [PY, "-m", "benchmarks.live.diagnose_methodology",
           "--suite", suite, "--model", model, "--n-user", str(n_user),
           "--ablations", ablations, "--out", str(out)]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=_env())
    if proc.returncode != 0 or not out.exists():
        print(proc.stdout[-800:], file=sys.stderr)
        print(proc.stderr[-800:], file=sys.stderr)
        return {}
    return json.loads(out.read_text())


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Repeat a live run and report the spread")
    p.add_argument("--suite", default="travel")
    p.add_argument("--model", default="gpt-4o-mini-2024-07-18")
    p.add_argument("--n-user", type=int, default=8)
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--ablations", default="envelope-taint,envelope-taint-deferallow")
    p.add_argument("--json", type=Path, default=None)
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    runs = []
    with tempfile.TemporaryDirectory() as tmp:
        for i in range(args.repeats):
            trace = one_run(args.suite, args.model, args.n_user, args.ablations,
                            Path(tmp) / f"run{i}.json")
            if trace:
                runs.append(summarize(trace))
            print(f"  run {i + 1}/{args.repeats} done", file=sys.stderr)

    if not runs:
        print("no runs completed", file=sys.stderr)
        return 2

    ablations = list(runs[0])
    print(f"# Repeated live runs, {args.suite}, {args.model}, "
          f"n={args.n_user} x {len(runs)} repeats\n")
    print("| Ablation | autonomous (pooled) | per-run | spread | hard DENYs | step-ups |")
    print("| --- | --- | --- | --: | --: | --: |")
    report = {}
    for ablation in ablations:
        autos = [r[ablation]["autonomous"] for r in runs if ablation in r]
        ns = [r[ablation]["n"] for r in runs if ablation in r]
        denies = sum(r[ablation]["false_block"] for r in runs if ablation in r)
        steps = sum(r[ablation]["stepups"] for r in runs if ablation in r)
        pooled = proportion_ci(sum(autos), sum(ns))
        per_run = ", ".join(f"{a / n:.0%}" for a, n in zip(autos, ns))
        spread = (max(a / n for a, n in zip(autos, ns))
                  - min(a / n for a, n in zip(autos, ns))) if autos else 0.0
        print(f"| {ablation} | {pooled.render()} | {per_run} | {spread:.0%} | {denies} | {steps} |")
        report[ablation] = {
            "pooled": pooled.summary(), "per_run": [a / n for a, n in zip(autos, ns)],
            "spread": round(spread, 4), "hard_denies": denies, "stepups": steps,
        }

    widest = max((v["spread"] for v in report.values()), default=0.0)
    print(f"\nWidest run-to-run spread: **{widest:.0%}**. Any difference between "
          "ablations smaller than this is not resolved by this experiment, however "
          "the pooled point estimates happen to order themselves.")

    if args.json:
        args.json.write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
