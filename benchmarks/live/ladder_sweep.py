"""The two sweeps that decide whether the aggregate-class result is publishable.

    python -m benchmarks.live.ladder_sweep --stage cross
    python -m benchmarks.live.ladder_sweep --stage seeds

`phase0` gives 0/100 for the ledger against 100/100 for both baselines on four
scenarios, on one model. That is not yet a result, for two separate reasons, and
this module measures each.

**Cross-model.** The one model was `gpt-5-mini`, reached through a deployment
named `gpt-4o-mini-2024-07-18` (see `ModelIdentity`). A containment number from a
single model cannot distinguish a property of the mechanism from a property of
that model's tool-calling habits, and `improvements.md` stakes a claim on model
strength being the axis that moves these numbers. So the same four scenarios run
against `gpt-4.1-mini` and `gpt-4.1`, which are different families rather than
different sizes of the same one.

**Seed spread.** `frontier.md` records identical config, suite, model and attack
giving 27.8% ASR in one sweep and 0.0% in another. W4 therefore requires at least
five seeds per published cell and the BETWEEN-seed spread reported beside the
pooled interval, because they answer different questions: the interval says how
precisely this sweep measured itself, and the spread says whether another sweep
would have found the same thing.

Runs strictly serially. The concurrent version of this froze the machine.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from benchmarks.core.reporting import format_rate
from benchmarks.live.bpl_live import run

OUT = Path(__file__).parent.parent / "results" / "phase0"
SCENARIOS = ("payout-splitting", "refund-structuring",
             "access-grant-sprawl", "bulk-delete-retention")
CONDITIONS = ["none", "progent", "camel", "clayseal"]
LADDER = ("gpt-4.1-mini", "gpt-4.1")


def _cell(model: str, scenario: str, runs: int, seed: int | None) -> dict:
    print(f"\n=== {model} / {scenario} / seed={seed} / n={runs}")
    return run(model, runs, scenario, CONDITIONS, seed=seed)


def stage_cross(runs: int) -> dict:
    """Does the result reproduce on a different model family?"""
    out: dict = {}
    for model in LADDER:
        out[model] = {s: _cell(model, s, runs, 0) for s in SCENARIOS}
    return out


def stage_seeds(runs: int, seeds: int, model: str, scenario: str) -> dict:
    """How much does an identical cell move when only the seed changes?"""
    return {str(sd): _cell(model, scenario, runs, sd)
            for sd in range(1, seeds + 1)}


def _report_seeds(cells: dict) -> None:
    print("\nbetween-seed spread\n")
    print(f"{'condition':<10}{'min':>8}{'max':>8}{'spread':>9}{'pooled':>28}")
    print("-" * 63)
    for cond in CONDITIONS:
        rates = [c[cond]["violation_rate"] for c in cells.values()
                 if cond in c]
        if not rates:
            continue
        ns = [c[cond]["n"] for c in cells.values() if cond in c]
        hits = sum(round(r * n) for r, n in zip(rates, ns))
        pooled = format_rate(hits, sum(ns), seeds=len(rates))
        print(f"{cond:<10}{min(rates)*100:7.1f}%{max(rates)*100:7.1f}%"
              f"{(max(rates)-min(rates))*100:8.1f}%{pooled:>28}")
    # The spread is the finding, not a caveat on it. A cell whose seeds disagree
    # by more than its own interval is a cell whose interval understates it.
    print("\nA condition whose spread exceeds its pooled interval width is not "
          "measured by that interval.")


def _report_cross(cells: dict) -> None:
    print("\ncross-model replication\n")
    head = f"{'model':<14}{'scenario':<24}{'cond':<10}{'violation':>26}"
    print(head)
    print("-" * len(head))
    for model, by_scen in cells.items():
        for scen, by_cond in by_scen.items():
            for cond in CONDITIONS:
                m = by_cond.get(cond)
                if not m:
                    continue
                n = m["n"]
                hits = round(m["violation_rate"] * n)
                print(f"{model:<14}{scen:<24}{cond:<10}"
                      f"{format_rate(hits, n):>26}")
        print()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--stage", choices=("cross", "seeds"), required=True)
    p.add_argument("--runs", type=int, default=25)
    p.add_argument("--seeds", type=int, default=5)
    p.add_argument("--model", default="gpt-4.1-mini")
    p.add_argument("--scenario", default="payout-splitting")
    args = p.parse_args(argv)

    OUT.mkdir(parents=True, exist_ok=True)
    if args.stage == "cross":
        cells = stage_cross(args.runs)
        _report_cross(cells)
        dest = OUT / "cross_model.json"
    else:
        cells = stage_seeds(args.runs, args.seeds, args.model, args.scenario)
        _report_seeds(cells)
        dest = OUT / f"seed_spread_{args.model}_{args.scenario}.json"

    dest.write_text(json.dumps(cells, indent=2))
    print(f"\nwrote {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
