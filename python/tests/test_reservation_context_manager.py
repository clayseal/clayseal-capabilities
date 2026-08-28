"""`with budget.reserve(...)` settles the hold on the way out.

A reservation is two-phase: `reserve` holds against the ceiling and the caller
must then `commit` or `release`. Written out by hand the failure mode is a
reservation that is never settled, which holds for the life of the session, so
the budget quietly shrinks and later legitimate calls are refused with
`value_budget_exceeded` for spend that never happened.

The `with` form cannot leak, and on an exception it releases rather than
commits, which is the direction that cannot overcharge.
"""
from __future__ import annotations

from decimal import Decimal

import pytest

from clayseal.capabilities.value_budget import SessionValueBudget, ValueBudgetConfig


def _budget(ceiling="100.00") -> SessionValueBudget:
    return SessionValueBudget(config=ValueBudgetConfig(
        tracked={"pay": ("amount", "spend")}, ceilings={"spend": ceiling}))


def test_a_clean_exit_commits():
    b = _budget()
    with b.reserve("pay", {"amount": "30.00"}) as res:
        assert res.allowed, res.reason
    assert b.spent["spend"] == Decimal("30.00")
    assert b._reserved.get("spend", Decimal(0)) == Decimal(0)


def test_an_exception_releases_rather_than_commits():
    """A call that did not complete has not spent."""
    b = _budget()
    with pytest.raises(RuntimeError):
        with b.reserve("pay", {"amount": "30.00"}) as res:
            assert res.allowed
            raise RuntimeError("the tool blew up")
    assert b.spent.get("spend", Decimal(0)) == Decimal(0)
    assert b._reserved.get("spend", Decimal(0)) == Decimal(0)


def test_a_refused_reservation_settles_to_nothing():
    b = _budget("10.00")
    with b.reserve("pay", {"amount": "99.00"}) as res:
        assert not res.allowed
    assert b.spent.get("spend", Decimal(0)) == Decimal(0)
    assert b._reserved.get("spend", Decimal(0)) == Decimal(0)


def test_the_ceiling_is_reached_exactly_and_not_halved():
    """The whole point: N calls of the ceiling/N must all fit.

    Pairing `reserve` with the module-level `commit(tool, args)` instead of
    `res.commit()` books the amount twice and this arrives at 5 rather than 10,
    which is what the docstring on that method now warns about.
    """
    b = _budget("100.00")
    allowed = 0
    for _ in range(20):
        with b.reserve("pay", {"amount": "10.00"}) as res:
            if res.allowed:
                allowed += 1
    assert allowed == 10, allowed
    assert b.spent["spend"] == Decimal("100.00")


def test_the_hand_written_form_still_works():
    """The context manager is an addition, not a replacement."""
    b = _budget()
    res = b.reserve("pay", {"amount": "30.00"})
    assert res.allowed
    res.commit()
    assert b.spent["spend"] == Decimal("30.00")
