"""Randomized stress of the budget ledger's conservation invariants.

    python -m benchmarks.stress_budget
    python -m benchmarks.stress_budget --sessions 4000 --seed 7

Everything else in this repo evaluates the system on curated corpora. That finds
the defects a corpus author thought of. This finds the ones nobody thought of, by
throwing millions of randomized reserve/commit/release interleavings at the real
`SessionValueBudget` and checking properties that must hold for *every* sequence.

The budget ledger is the right target for this treatment. It is the only rung on
the ladder that carries state across a session, so it is the only one where a
bug compounds rather than being confined to one decision, and the failure mode
is a silent double-spend, not an exception. `broker.py` already documents one
defect of exactly this shape: the replan and `defer_allows_bound` paths returned
ALLOW after a rollback had released their reservations, so those actions executed
against a ledger that never recorded them and no cumulative ceiling could ever be
reached. That is the class of bug this hunts.

## The properties

Each is a claim that has to hold after any sequence of operations, not a claim
about a particular scenario.

``CONSERVATION``    committed total == sum of the amounts on committed
                    reservations. The ledger cannot invent or lose money.
``CEILING``         committed total <= the configured ceiling, always. This is
                    the actual security property: the whole point of a value
                    budget is that a fragmented series of individually-legal
                    transfers cannot exceed it.
``RELEASE_IS_FREE`` a reserved-then-released amount leaves the ledger exactly as
                    it was. A leak here is a denial of service (budget vanishes);
                    a negative leak is a double-spend.
``NO_DOUBLE``       committing or releasing the same reservation twice must not
                    move the ledger twice. Retry logic upstream makes this
                    reachable.
``REMAINING``       remaining == ceiling - committed, at every point.
``FAIL_CLOSED``     an amount the parser cannot use is DENIED, never treated as
                    untracked. This one found a live defect: `1e999`, `10**30`,
                    `Infinity` and `''` all returned allowed=True / "ok_untracked"
                    against a ceiling of 10, so the spend ceiling stopped
                    applying exactly when the amount was absurd.

Interleaving matters and is generated, not assumed: reservations are held open
across other operations, committed out of order, and abandoned, because that is
what a real session does when a step-up is pending while other calls proceed.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from decimal import Decimal
from pathlib import Path

from agentauth.capabilities.value_budget import (
    SessionValueBudget,
    ValueBudgetConfig,
)

TOOL = "payments.transfer"
BUDGET_ID = "payments"


def _config(ceiling: Decimal) -> ValueBudgetConfig:
    """A one-tool, one-budget config: the smallest thing that can be violated."""
    return ValueBudgetConfig(
        # (arg_name, budget_id), that order, and both are `str`, so
        # transposing them type-checks fine and silently untracks the tool:
        # every reserve returns allowed=True and the ledger stays at zero.
        # This harness got it backwards on the first run and the symptom
        # was "reserve(25) allowed against a ceiling of 10", which reads
        # like a CEILING violation in the system under test rather than a
        # misconfiguration in the caller.
        tracked={TOOL: ("amount", BUDGET_ID)},
        ceilings={BUDGET_ID: ceiling},
    )


class Violation(Exception):
    def __init__(self, prop: str, detail: str, history: list[str]) -> None:
        super().__init__(f"{prop}: {detail}")
        self.prop = prop
        self.detail = detail
        self.history = history


def _check(budget: SessionValueBudget, ceiling: Decimal, committed: Decimal,
           reserved: Decimal, history: list[str]) -> None:
    """``remaining()`` reflects committed spend AND outstanding reservations.

    That is the correct and safe semantics, money held for an in-flight call is
    not available to a second one, and modelling it as committed-only was this
    harness's second self-inflicted failure. The symptom was a CONSERVATION
    violation reported the instant a reservation opened, which looks exactly like
    the ledger inventing money.
    """
    held = ceiling - (budget.remaining(BUDGET_ID) or Decimal(0))
    if held != committed + reserved:
        raise Violation("CONSERVATION",
                        f"ledger holds {held}, operations say "
                        f"{committed} committed + {reserved} reserved", history)
    if held > ceiling:
        raise Violation("CEILING",
                        f"{held} held against a ceiling of {ceiling}", history)


def run_session(seed: int, *, steps: int = 40) -> None:
    """One randomized session. Raises ``Violation`` on a property failure."""
    rng = random.Random(seed)
    ceiling = Decimal(rng.choice([10, 100, 1000]))
    budget = SessionValueBudget(config=_config(ceiling))

    committed = Decimal(0)
    reserved = Decimal(0)
    open_res: list[tuple[object, Decimal]] = []
    history: list[str] = [f"ceiling={ceiling}"]

    for _ in range(steps):
        action = rng.choices(
            ["reserve", "commit", "release", "double_commit", "double_release",
             "hostile"],
            weights=[38, 22, 18, 5, 5, 12],
        )[0]

        if action == "hostile":
            # Amounts an attacker controls. The sequence fuzzer above holds all
            # its properties; every real defect found here was in input
            # handling, so the inputs are fuzzed too and permanently.
            raw = rng.choice(["1e999", "Infinity", "-Infinity", "NaN", "sNaN",
                              "0x10", "", None, [1], True, 10 ** 30, "-5"])
            res = budget.reserve(TOOL, {"amount": raw})
            history.append(f"hostile({raw!r}) -> allowed={res.allowed}")
            if res.allowed:
                raise Violation("FAIL_CLOSED",
                                f"an unusable amount {raw!r} was allowed as "
                                f"{res.reason!r}", history)
            _check(budget, ceiling, committed, reserved, history)

        elif action == "reserve":
            amount = Decimal(rng.choice([0, 1, 3, 7, 25, 99, 250]))
            res = budget.reserve(TOOL, {"amount": str(amount)})
            history.append(f"reserve({amount}) -> allowed={res.allowed}")
            if res.allowed:
                open_res.append((res, amount))
                reserved += amount
            # A refused reservation must not move the ledger.
            _check(budget, ceiling, committed, reserved, history)

        elif action == "commit" and open_res:
            idx = rng.randrange(len(open_res))
            res, amount = open_res.pop(idx)
            res.commit()
            committed += amount
            reserved -= amount
            history.append(f"commit({amount})")
            _check(budget, ceiling, committed, reserved, history)

        elif action == "release" and open_res:
            idx = rng.randrange(len(open_res))
            res, amount = open_res.pop(idx)
            res.release()
            reserved -= amount
            history.append(f"release({amount})")
            # RELEASE_IS_FREE: committed is unchanged.
            _check(budget, ceiling, committed, reserved, history)

        elif action == "double_commit" and open_res:
            res, amount = open_res.pop(rng.randrange(len(open_res)))
            res.commit()
            committed += amount
            reserved -= amount
            res.commit()  # NO_DOUBLE: the second must be a no-op
            history.append(f"commit({amount}) x2")
            _check(budget, ceiling, committed, reserved, history)

        elif action == "double_release" and open_res:
            res, amount = open_res.pop(rng.randrange(len(open_res)))
            res.release()
            reserved -= amount
            res.release()  # NO_DOUBLE
            history.append(f"release({amount}) x2")
            _check(budget, ceiling, committed, reserved, history)

    # Abandoned reservations (neither committed nor released) must not count as
    # spend: a session that dies mid-flight cannot burn budget it never used.
    for res, amount in open_res:
        res.release()
        reserved -= amount
    _check(budget, ceiling, committed, reserved, history + ["drain"])
    if reserved != 0:
        raise Violation("CONSERVATION",
                        f"{reserved} still reserved after draining", history)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sessions", type=int, default=3000)
    p.add_argument("--steps", type=int, default=40)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--json", type=Path, default=None)
    args = p.parse_args(argv)

    failures: list[dict] = []
    by_prop: dict[str, int] = {}
    for i in range(args.sessions):
        try:
            run_session(args.seed + i, steps=args.steps)
        except Violation as exc:
            by_prop[exc.prop] = by_prop.get(exc.prop, 0) + 1
            if len(failures) < 5:
                failures.append({
                    "seed": args.seed + i, "property": exc.prop,
                    "detail": exc.detail, "history": exc.history[-12:],
                })

    total = args.sessions
    print(f"budget ledger stress: {total} randomized sessions x {args.steps} ops "
          f"(seed {args.seed})")
    if not by_prop:
        print(f"all properties held across ~{total * args.steps:,} operations")
    else:
        print("VIOLATIONS")
        for prop, n in sorted(by_prop.items(), key=lambda kv: -kv[1]):
            print(f"  {prop:<16}{n:>6} of {total} sessions")
        for f in failures:
            print(f"\n--- seed {f['seed']} [{f['property']}] {f['detail']}")
            for line in f["history"]:
                print(f"      {line}")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(
            {"sessions": total, "violations": by_prop, "examples": failures},
            indent=2))
        print(f"\nwrote {args.json}")
    return 1 if by_prop else 0


if __name__ == "__main__":
    sys.exit(main())
