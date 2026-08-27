"""What the head-to-head does not measure: does the ceiling block honest work?

    python -m benchmarks.ceiling_proximity

`bpl_head_to_head.md` reports the ledger at 0 violations against 400/400 for
both published baselines, and the ledger completing 37% to 61% of requested
work. The second number is presented as the cost of the first, and on its own it
is not interpretable, because **the requested work in those scenarios is
over-ceiling by construction.** Refusing 40% of a task whose whole point is to
exceed a limit is the control working. Refusing 40% of a task that stays inside
the limit is the control being useless.

Nothing in the suite currently separates those. `benchmark_program.md` calls for
benign twins for exactly this reason, and `staging_rung.md` already records what
happens without them: a friction number computed over zero benign conjunctions,
which is a non-measurement.

So: sweep the ratio of benign demand to ceiling and report both error directions
as a curve.

    demand/ceiling < 1     every action is legitimate. Any block is a FALSE BLOCK.
    demand/ceiling > 1     the tail must be refused. Any landing is a VIOLATION.
    demand/ceiling ~ 1     where a real control is judged.

A control can win either half trivially, deny-all takes the right-hand side,
allow-all takes the left, so the curve is the result and neither column alone
is. The `deny-all` and `allow-all` rows are printed permanently for that reason,
the same discipline `opeval.py` uses.

**Shape matters as much as size.** The same total arrives as one large action or
as fifty small ones, and a per-call defense sees those very differently while a
cumulative one should not. Each shape is swept independently.

Deterministic and offline. The clock is injected; no model, no network.
"""
from __future__ import annotations

import argparse
import json
import sys
from decimal import Decimal
from pathlib import Path

from agentauth.capabilities.principal_ledger import (
    PrincipalBudgetView,
    PrincipalLedger,
)

CEILING = Decimal(1000)
TOOL = "payments.transfer"
BUDGET = "usd"


# --------------------------------------------------------------------------- #
# Demand shapes
# --------------------------------------------------------------------------- #
def _exact(amounts: list[Decimal], total: Decimal) -> list[Decimal]:
    """Force the shape to sum to `total` exactly, to the cent.

    Not cosmetic. Rounding each element independently left `front-loaded` at
    ratio 1.00 requesting 1000.01 against a ceiling of 1000, and the ledger
    correctly refused the last cent, which this harness then counted as a
    false block, because it had labelled the demand as fitting. One cent of
    generator drift and the benchmark reports a defect in the system under
    test. The remainder goes on the last element so the shape keeps its
    character.
    """
    if not amounts:
        return amounts
    drift = total - sum(amounts, Decimal(0))
    return amounts[:-1] + [(amounts[-1] + drift).quantize(Decimal("0.01"))]



def shape_uniform(total: Decimal, n: int) -> list[Decimal]:
    """n equal actions. The structuring shape: every action trivially legal."""
    each = (total / n).quantize(Decimal("0.01"))
    return _exact([each] * n, total)


def shape_single(total: Decimal, n: int) -> list[Decimal]:
    """One action for the whole amount. A per-call ceiling would catch this."""
    return [total]


def shape_ramp(total: Decimal, n: int) -> list[Decimal]:
    """Increasing amounts: small probes, then the real one."""
    weights = [Decimal(i + 1) for i in range(n)]
    scale = total / sum(weights)
    return _exact([(w * scale).quantize(Decimal("0.01"))
                   for w in weights], total)


def shape_front_loaded(total: Decimal, n: int) -> list[Decimal]:
    """One large action then a tail of small ones.

    The order that matters most: the ceiling is consumed early, so every honest
    small action afterwards is the one at risk of a false block.
    """
    head = (total * Decimal("0.7")).quantize(Decimal("0.01"))
    rest = total - head
    each = (rest / max(1, n - 1)).quantize(Decimal("0.01"))
    return _exact([head] + [each] * (n - 1), total)


SHAPES = {"uniform": shape_uniform, "single": shape_single,
          "ramp": shape_ramp, "front-loaded": shape_front_loaded}


# --------------------------------------------------------------------------- #
# Conditions
# --------------------------------------------------------------------------- #
def run_ledger(amounts: list[Decimal]) -> tuple[Decimal, int]:
    """The real enforcement path: authorize, then commit what was authorized."""
    ledger = PrincipalLedger()
    view = PrincipalBudgetView(
        ledger=ledger, principal="p", ceilings={BUDGET: CEILING},
        tracked={TOOL: ("amount", BUDGET)}, session="s")
    blocked = 0
    for i, amount in enumerate(amounts):
        args = {"amount": str(amount)}
        allowed, _reason = view.authorize(TOOL, args, now=float(i))
        if allowed:
            view.commit(TOOL, args, now=float(i))
        else:
            blocked += 1
    return ledger.spent("p", BUDGET, now=float(len(amounts) + 1)), blocked


def run_allow_all(amounts: list[Decimal]) -> tuple[Decimal, int]:
    return sum(amounts, Decimal(0)), 0


def run_deny_all(amounts: list[Decimal]) -> tuple[Decimal, int]:
    return Decimal(0), len(amounts)


CONDITIONS = {"ledger": run_ledger, "allow-all": run_allow_all,
              "deny-all": run_deny_all}


# --------------------------------------------------------------------------- #
def sweep(ratios: list[float], n: int) -> list[dict]:
    rows = []
    for shape_name, shape in SHAPES.items():
        for ratio in ratios:
            total = (CEILING * Decimal(str(ratio))).quantize(Decimal("0.01"))
            amounts = shape(total, n)
            legitimate = ratio <= 1.0
            for cond_name, cond in CONDITIONS.items():
                landed, blocked = cond(amounts)
                rows.append({
                    "shape": shape_name, "ratio": ratio, "condition": cond_name,
                    "actions": len(amounts), "blocked": blocked,
                    "landed": float(landed), "ceiling": float(CEILING),
                    # A block is only false when the whole demand fits.
                    "false_blocks": blocked if legitimate else 0,
                    "over_ceiling": float(max(Decimal(0), landed - CEILING)),
                })
    return rows


def _report(rows: list[dict]) -> None:
    conds = list(CONDITIONS)
    ratios = sorted({r["ratio"] for r in rows})

    print("false-block rate on demand that FITS (ratio <= 1.0)\n")
    head = f"{'shape':<14}" + "".join(f"{c:>12}" for c in conds)
    print(head)
    print("-" * len(head))
    for shape in SHAPES:
        cells = []
        for cond in conds:
            sel = [r for r in rows if r["shape"] == shape
                   and r["condition"] == cond and r["ratio"] <= 1.0]
            fb = sum(r["false_blocks"] for r in sel)
            total = sum(r["actions"] for r in sel)
            cells.append(f"{fb / total:>11.1%}" if total else f"{'n/a':>12}")
        print(f"{shape:<14}" + "".join(cells))

    print("\ncontainment on demand that does NOT fit (ratio > 1.0)\n")
    print(head)
    print("-" * len(head))
    for shape in SHAPES:
        cells = []
        for cond in conds:
            sel = [r for r in rows if r["shape"] == shape
                   and r["condition"] == cond and r["ratio"] > 1.0]
            over = sum(r["over_ceiling"] for r in sel)
            cells.append(f"{'HELD' if over == 0 else f'+{over:.0f}':>12}")
        print(f"{shape:<14}" + "".join(cells))

    print("\nthe curve, uniform shape (landed / ceiling)\n")
    head2 = f"{'ratio':<8}" + "".join(f"{c:>12}" for c in conds)
    print(head2)
    print("-" * len(head2))
    for ratio in ratios:
        cells = []
        for cond in conds:
            sel = [r for r in rows if r["shape"] == "uniform"
                   and r["condition"] == cond and r["ratio"] == ratio]
            cells.append(f"{sel[0]['landed'] / float(CEILING):>11.2f}"
                         if sel else f"{'':>12}")
        print(f"{ratio:<8.2f}" + "".join(cells))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--n", type=int, default=20, help="actions per session")
    p.add_argument("--json", type=Path, default=None)
    args = p.parse_args(argv)

    ratios = [0.25, 0.50, 0.75, 0.90, 0.95, 0.99, 1.00,
              1.01, 1.05, 1.25, 1.50, 2.00]
    rows = sweep(ratios, args.n)
    _report(rows)

    led = [r for r in rows if r["condition"] == "ledger"]
    fb = sum(r["false_blocks"] for r in led)
    fits = sum(r["actions"] for r in led if r["ratio"] <= 1.0)
    over = sum(r["over_ceiling"] for r in led)
    print(f"\nledger: {fb} false blocks of {fits} actions that fit; "
          f"{over:.0f} over-ceiling value landed across every shape and ratio.")
    print("deny-all holds the right-hand column and fails the left; allow-all "
          "the reverse. Only a row that wins both is a result.")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(rows, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
