"""The rolling-window value budget: "no more than $X per 24 hours".

The rule most business policies are written as, and the one no rung could express.
`SessionValueBudget` sums forever, `SessionVelocity` windows counts. Approximating
a rolling ceiling with a session ceiling is wrong in both directions at once, and
`benchmarks/results/bpl_suite_composition.md` names the measured case:
`rolling-window-hour-skew` was the one scenario in 132 where this gateway lost
real work, refusing a benign script that paid $2,000, waited 24 hours, and paid
$2,000 again.

Every test drives an injected clock. A windowed control tested against the wall
clock is a windowed control nobody can verify.
"""
from __future__ import annotations

from decimal import Decimal

import pytest

from agentauth.capabilities.value_budget import (
    EffectSpec,
    SessionValueBudget,
    ValueBudgetConfig,
)
from agentauth.capabilities.windowed_budget import WindowedValueBudget

HOUR = 3600.0


class Clock:
    """A clock the test moves, because a rolling window is about time."""

    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def advance(self, hours: float) -> None:
        self.t += hours * HOUR


def _budget(ceiling="3000", window=24 * HOUR, **kw):
    clock = Clock()
    config = ValueBudgetConfig(tracked={"pay": ("amount", "roll")},
                              ceilings={"roll": ceiling})
    return WindowedValueBudget(config=config, windows={"roll": window},
                               clock=clock, **kw), clock


def _pay(budget, amount, **args) -> tuple[bool, str]:
    res = budget.reserve("pay", {"amount": amount, **args})
    if res.allowed:
        res.commit()
    return res.allowed, res.reason


# --------------------------------------------------------------------------- #
# The measured case
# --------------------------------------------------------------------------- #
def test_two_payments_a_day_apart_are_both_allowed():
    """The benign script a session budget refused.

    Legal under a rolling window because the two payments never coexist in one.
    """
    budget, clock = _budget(ceiling="3000", window=24 * HOUR)
    assert _pay(budget, 2000)[0] is True
    clock.advance(24)
    assert _pay(budget, 2000)[0] is True, "the first payment should have aged out"


def test_two_payments_six_hours_apart_are_not():
    """The attack. Same two amounts, inside one window."""
    budget, clock = _budget(ceiling="3000", window=24 * HOUR)
    assert _pay(budget, 2000)[0] is True
    clock.advance(6)
    allowed, reason = _pay(budget, 2000)
    assert allowed is False
    assert reason == "value_budget_exceeded"


def test_a_session_budget_cannot_tell_those_two_apart():
    """The reason this class exists, stated as a test.

    The same pair of scripts, against the rung that was standing in for a rolling
    ceiling. It refuses both, so it contained the attack for a reason unrelated to
    the rule and lost the benign work for the same one.
    """
    session = SessionValueBudget(config=ValueBudgetConfig(
        tracked={"pay": ("amount", "roll")}, ceilings={"roll": "3000"}))
    for _ in range(1):
        res = session.reserve("pay", {"amount": 2000})
        assert res.allowed
        res.commit()
    # No amount of elapsed time changes this: there is no time in it.
    assert session.reserve("pay", {"amount": 2000}).allowed is False


# --------------------------------------------------------------------------- #
# Eviction
# --------------------------------------------------------------------------- #
def test_the_window_is_rolling_and_not_a_reset():
    """Three payments, each 10 hours apart, ceiling 3000, window 24h.

    A tumbling window would clear at a boundary and allow all three. A rolling
    one keeps the last 24 hours, so the third sees the second still in scope.
    """
    budget, clock = _budget(ceiling="3000", window=24 * HOUR)
    assert _pay(budget, 2000)[0] is True         # t=0
    clock.advance(10)
    assert _pay(budget, 2000)[0] is False        # t=10, first still counts
    clock.advance(15)
    assert _pay(budget, 2000)[0] is True         # t=25, first aged out


def test_an_entry_exactly_at_the_boundary_has_aged_out():
    """`now - at < window` keeps it; equality drops it. Stated so the boundary is
    a decision rather than an accident of a comparison operator."""
    budget, clock = _budget(ceiling="2000", window=24 * HOUR)
    assert _pay(budget, 2000)[0] is True
    clock.advance(24)
    assert budget.in_window("roll") == 0
    assert _pay(budget, 2000)[0] is True


def test_totals_are_recomputed_rather_than_subtracted():
    """Decimal exactness over many evictions.

    Subtracting on eviction accumulates error and a ceiling that drifts is not a
    ceiling. Recomputing from the surviving entries cannot drift.
    """
    budget, clock = _budget(ceiling="1000", window=1 * HOUR)
    for i in range(200):
        if i:
            clock.advance(2)                      # each ages out before the next
        assert _pay(budget, "0.01")[0] is True
    # Exactly one entry survives, and the total is that entry and not a
    # subtraction of 199 others from 200.
    assert budget.in_window("roll") == 1
    assert budget.spent["roll"] == Decimal("0.01")


def test_remaining_reflects_the_window():
    budget, clock = _budget(ceiling="3000", window=24 * HOUR)
    _pay(budget, 2000)
    assert budget.remaining("roll") == Decimal("1000.00")
    clock.advance(25)
    assert budget.remaining("roll") == Decimal("3000")


# --------------------------------------------------------------------------- #
# What ages out with an entry
# --------------------------------------------------------------------------- #
def test_an_object_identity_is_released_when_its_entry_ages_out():
    """"No more than one payment per invoice per day" frees the invoice tomorrow.

    Holding the identity forever would apply the window to amounts and not to
    identities, which is a half-applied control.
    """
    clock = Clock()
    config = ValueBudgetConfig(
        tracked={"pay": EffectSpec(budget_id="roll", amount_arg="amount",
                                   identity_args=("invoice",))},
        ceilings={"roll": "100000"})
    budget = WindowedValueBudget(config=config, windows={"roll": 24 * HOUR},
                                 clock=clock)
    assert _pay(budget, 500, invoice="INV-1")[0] is True
    again = _pay(budget, 500, invoice="INV-1")
    assert again[0] is False, "the same invoice inside the window must not repeat"
    clock.advance(25)
    assert _pay(budget, 500, invoice="INV-1")[0] is True


def test_a_budget_with_no_window_behaves_exactly_as_its_parent():
    """The default has to change nothing: every published number was measured
    without a window, and adding this class must not move one."""
    clock = Clock()
    config = ValueBudgetConfig(tracked={"pay": ("amount", "flat")},
                              ceilings={"flat": "3000"})
    windowed = WindowedValueBudget(config=config, windows={}, clock=clock)
    session = SessionValueBudget(config=config)

    for budget in (windowed, session):
        assert budget.reserve("pay", {"amount": 2000}).allowed is True

    windowed_res = windowed.reserve("pay", {"amount": 2000})
    session_res = session.reserve("pay", {"amount": 2000})
    assert windowed_res.allowed == session_res.allowed
    clock.advance(1000)
    assert windowed.reserve("pay", {"amount": 2000}).allowed is False


def test_a_budget_id_without_a_window_is_unaffected_by_one_that_has_it():
    clock = Clock()
    config = ValueBudgetConfig(
        tracked={"pay": ("amount", "roll"), "wire": ("amount", "flat")},
        ceilings={"roll": "3000", "flat": "3000"})
    budget = WindowedValueBudget(config=config, windows={"roll": 24 * HOUR},
                                 clock=clock)
    assert budget.reserve("wire", {"amount": 2000}).allowed is True
    budget.reserve("wire", {"amount": 2000}).release()
    budget.commit("wire", {"amount": 2000})
    clock.advance(1000)
    assert budget.reserve("wire", {"amount": 2000}).allowed is False, (
        "the unwindowed budget id aged something out"
    )


# --------------------------------------------------------------------------- #
# Refusals
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("window", [0, -1, -3600.0, "24h", None])
def test_a_malformed_window_is_refused_at_construction(window):
    """A window of zero evicts everything immediately and keeps looking like a
    ceiling. Every way of absorbing that quietly is worse than refusing it."""
    with pytest.raises(ValueError, match="positive number"):
        WindowedValueBudget(
            config=ValueBudgetConfig(tracked={"pay": ("amount", "roll")},
                                     ceilings={"roll": "1"}),
            windows={"roll": window})


def test_a_released_reservation_does_not_enter_the_ledger():
    """A refused downstream call must not consume window headroom."""
    budget, clock = _budget(ceiling="3000", window=24 * HOUR)
    res = budget.reserve("pay", {"amount": 2000})
    assert res.allowed
    res.release()
    assert budget.in_window("roll") == 0
    assert _pay(budget, 2000)[0] is True


def test_committing_a_reservation_twice_books_it_once():
    budget, _ = _budget(ceiling="3000", window=24 * HOUR)
    res = budget.reserve("pay", {"amount": 2000})
    res.commit()
    res.commit()
    assert budget.in_window("roll") == 1
    assert budget.spent["roll"] == Decimal("2000.00")


def test_the_ceiling_holds_under_concurrent_callers():
    """The parent's TOCTOU-free reserve is inherited, and eviction must not
    reopen the race it closes."""
    import threading

    budget, _ = _budget(ceiling="3000", window=24 * HOUR)
    results: list[bool] = []
    lock = threading.Lock()
    barrier = threading.Barrier(16)

    def worker() -> None:
        barrier.wait()
        allowed, _ = _pay(budget, 2000)
        with lock:
            results.append(allowed)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1, results


def test_to_dict_reports_the_window_and_what_is_in_it():
    budget, clock = _budget(ceiling="3000", window=24 * HOUR)
    _pay(budget, 1000)
    snapshot = budget.to_dict()
    assert snapshot["windows"] == {"roll": 24 * HOUR}
    assert snapshot["in_window"] == {"roll": 1}
