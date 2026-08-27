"""`PrincipalBudgetView` had two gates, and the one that disagreed failed open.

`would_allow` reads `ceilings` and `tracked`, the two things the constructor
advertises. `reserve` read `getattr(self, "config", None)` and returns
`ok_untracked` when there is none. `config` was not a field: `policy.py` set it
onto the instance after construction, so a view built any other way had none,
and `reserve` allowed everything.

Measured before the fix, ceiling 100, twenty calls of 10.00:

    would_allow + commit    10 of 20 allowed     correct
    reserve + commit        20 of 20 allowed     no ceiling at all

The reason string on all twenty was `ok_untracked`, so the audit trail said the
calls were not tracked rather than that the ceiling had been skipped.

This is the cross-session spend control, the one that stops structuring, and the
constructor invites exactly the hand-wiring that did not enforce. A policy-file
deployment was never affected, because `policy.py` assigns `config` immediately
after construction.

`config` is a declared field now, derived from `ceilings`/`tracked` when the
caller does not pass one, so both gates read one answer however the view is
built.
"""
from __future__ import annotations

from decimal import Decimal

import pytest

from clayseal.capabilities.principal_ledger import PrincipalBudgetView, PrincipalLedger

CEILING = Decimal("100.00")
TRACKED = {"pay": ("amount", "spend")}


def _view(ledger=None, **kw) -> PrincipalBudgetView:
    return PrincipalBudgetView(
        ledger=ledger or PrincipalLedger(), principal="agent-1",
        ceilings={"spend": CEILING}, tracked=TRACKED, session="s1", **kw)


def test_reserve_enforces_the_ceiling_it_was_constructed_with():
    view, allowed = _view(), 0
    for _ in range(20):
        res = view.reserve("pay", {"amount": "10.00"})
        if res.allowed:
            allowed += 1
            res.commit()
    assert allowed == 10, f"{allowed} of 20 allowed against a ceiling of 100"


def test_an_unsettled_reservation_still_holds_against_the_ceiling():
    """Holds are the point: a reservation not yet committed must occupy room."""
    view, allowed = _view(), 0
    for _ in range(20):
        if view.reserve("pay", {"amount": "10.00"}).allowed:
            allowed += 1
    assert allowed == 10, allowed


def test_both_gates_on_this_object_agree():
    """The defect was two gates on one object disagreeing, not either alone."""
    by_reserve, by_would_allow = 0, 0

    view = _view()
    for _ in range(20):
        res = view.reserve("pay", {"amount": "10.00"})
        if res.allowed:
            by_reserve += 1
            res.commit()

    view = _view()
    for _ in range(20):
        ok, _reason = view.would_allow("pay", {"amount": "10.00"})
        if ok:
            view.commit("pay", {"amount": "10.00"})
            by_would_allow += 1

    assert by_reserve == by_would_allow == 10, (by_reserve, by_would_allow)


def test_an_explicit_config_still_wins():
    """`policy.py` assigns `config` after construction; that must keep working."""
    from clayseal.capabilities.value_budget import ValueBudgetConfig

    view = _view()
    view.config = ValueBudgetConfig(tracked=TRACKED, ceilings={"spend": "30.00"})
    allowed = 0
    for _ in range(10):
        res = view.reserve("pay", {"amount": "10.00"})
        if res.allowed:
            allowed += 1
            res.commit()
    assert allowed == 3, allowed


def test_a_genuinely_untracked_call_is_still_untracked():
    """The fix must not turn 'no money spec' into a refusal."""
    view = _view()
    res = view.reserve("some_other_tool", {"amount": "10.00"})
    assert res.allowed and res.reason == "ok_untracked"

    bare = PrincipalBudgetView(ledger=PrincipalLedger(), principal="agent-1")
    res = bare.reserve("pay", {"amount": "10.00"})
    assert res.allowed and res.reason == "ok_untracked"


def test_the_refusal_names_the_ceiling_rather_than_claiming_untracked():
    """The old failure reported `ok_untracked` for calls it should have refused,
    so the audit trail agreed with the bug. The refusal has to be legible."""
    view = _view()
    for _ in range(10):
        res = view.reserve("pay", {"amount": "10.00"})
        assert res.allowed
        res.commit()
    res = view.reserve("pay", {"amount": "10.00"})
    assert not res.allowed
    assert res.reason == "value_budget_exceeded", res.reason


@pytest.mark.parametrize("bad", ["-10.00", "1e999", "NaN", "", "0x10"])
def test_bad_amounts_fail_closed_on_this_path_too(bad):
    """`reserve` returning `ok_untracked` for everything also meant these were
    allowed. The tri-state from `parse_amount` has to survive the fix."""
    res = _view().reserve("pay", {"amount": bad})
    assert not res.allowed, f"{bad!r} was allowed"
    assert res.reason in {"value_budget_negative_amount",
                          "value_budget_unparseable_amount"}, res.reason
