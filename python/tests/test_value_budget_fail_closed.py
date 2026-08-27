"""A spend ceiling must not stop applying when the amount is absurd.

Found by `benchmarks/stress_budget.py` fuzzing the amount field rather than the
operation sequence. The randomized reserve/commit/release interleavings held
across 200,000 operations; the defect was entirely in input handling, which is
the half a sequence fuzzer never reaches.
"""
from __future__ import annotations

from decimal import Decimal

import pytest

from clayseal.capabilities.value_budget import (
    SessionValueBudget,
    ValueBudgetConfig,
)

TOOL = "payments.transfer"


def _budget(ceiling: int = 10) -> SessionValueBudget:
    return SessionValueBudget(
        config=ValueBudgetConfig(tracked={TOOL: ("amount", "p")},
                                 ceilings={"p": Decimal(ceiling)}))


# The exact inputs that used to return allowed=True / "ok_untracked".
FAIL_OPEN_INPUTS = [
    "1e999",        # "transfer everything", and the most likely hostile value
    10 ** 30,       # an ordinary Python int that overflows cent-quantization
    "Infinity",
    "-Infinity",
    "NaN",          # also used to raise InvalidOperation out of reserve()
    "sNaN",
    "0x10",
    "",
    None,
    [5],
    {"a": 1},
    True,
]


@pytest.mark.parametrize("amount", FAIL_OPEN_INPUTS)
def test_an_unusable_amount_is_denied_rather_than_untracked(amount):
    """The fail-open, closed.

    ``_amount`` returned ``None`` for both "this tool has no money spec" and
    "the amount is garbage", and callers read that single value as untracked.
    So a ceiling of 10 allowed 1e999 and booked nothing, while the rest of the
    stack recorded that the budget rung had passed.
    """
    reservation = _budget().reserve(TOOL, {"amount": amount})
    assert not reservation.allowed, (
        f"{amount!r} was allowed with reason {reservation.reason!r}")
    assert reservation.reason == "value_budget_unparseable_amount"


@pytest.mark.parametrize("amount", FAIL_OPEN_INPUTS)
def test_an_unusable_amount_never_raises_out_of_the_gate(amount):
    """``Decimal('NaN')`` quantizes fine and then raises ``InvalidOperation`` on
    the ``amount < 0`` check, which escaped ``reserve`` and took the whole
    authorization call with it. An authorization gate may deny; it may not
    crash."""
    budget = _budget()
    budget.reserve(TOOL, {"amount": amount})       # must not raise
    budget.would_allow(TOOL, {"amount": amount})   # must not raise
    budget.commit(TOOL, {"amount": amount})        # must not raise
    assert budget.remaining("p") == Decimal(10), "an unusable amount booked spend"


@pytest.mark.parametrize("amount", FAIL_OPEN_INPUTS)
def test_would_allow_agrees_with_reserve(amount):
    """The preview and the gate must not disagree about a bad amount, or a
    dry-run pass reports clean and the live path denies."""
    allowed, reason = _budget().would_allow(TOOL, {"amount": amount})
    assert not allowed
    assert reason == "value_budget_unparseable_amount"


# --------------------------------------------------------------------------- #
# The behaviour that must NOT change.
# --------------------------------------------------------------------------- #
def test_a_tracked_call_with_no_amount_argument_is_still_untracked():
    """Genuinely absent is different from present-and-garbage, and only the
    second is an attack surface. Conflating them would deny legitimate calls to
    a money tool that simply carry no amount."""
    reservation = _budget().reserve(TOOL, {})
    assert reservation.allowed
    assert reservation.reason == "ok_untracked"


def test_an_untracked_tool_is_still_untracked():
    reservation = _budget().reserve("some.other.tool", {"amount": "1e999"})
    assert reservation.allowed
    assert reservation.reason == "ok_untracked"


def test_ordinary_amounts_are_unaffected():
    budget = _budget()
    ok = budget.reserve(TOOL, {"amount": "4"})
    assert ok.allowed and ok.reason == "ok"
    ok.commit()
    assert budget.remaining("p") == Decimal("6.00")

    assert budget.reserve(TOOL, {"amount": "-1"}).reason == "value_budget_negative_amount"
    assert budget.reserve(TOOL, {"amount": "25"}).reason == "value_budget_exceeded"


def test_the_ceiling_still_binds_across_fragmented_spend():
    """The property the rung exists for: many individually-legal transfers
    cannot sum past the ceiling."""
    budget = _budget(ceiling=10)
    for _ in range(3):
        reservation = budget.reserve(TOOL, {"amount": "3"})
        assert reservation.allowed
        reservation.commit()
    refused = budget.reserve(TOOL, {"amount": "3"})
    assert not refused.allowed
    assert budget.remaining("p") == Decimal("1.00")


# --------------------------------------------------------------------------- #
# The same fail-open, on the CEILING side, across all three budget rungs.
# --------------------------------------------------------------------------- #
BAD_CEILINGS = ["Infinity", "NaN", "1e999", "abc", [1], -5]


@pytest.mark.parametrize("ceiling", BAD_CEILINGS)
def test_a_value_budget_with_an_unusable_ceiling_cannot_be_built(ceiling):
    with pytest.raises(ValueError):
        ValueBudgetConfig(tracked={TOOL: ("amount", "p")},
                          ceilings={"p": ceiling})


@pytest.mark.parametrize("ceiling", BAD_CEILINGS)
def test_a_call_budget_with_an_unusable_ceiling_cannot_be_built(ceiling):
    from clayseal.capabilities.call_budget import CallBudgetConfig

    with pytest.raises(ValueError):
        CallBudgetConfig(tracked={TOOL: "p"}, ceilings={"p": ceiling})


@pytest.mark.parametrize("ceiling", BAD_CEILINGS)
def test_a_compute_budget_with_an_unusable_ceiling_cannot_be_built(ceiling):
    """The sharpest of the three before the fix.

    ``float('NaN')`` as a ceiling makes every ``projected > ceiling``
    comparison False, so nothing is ever refused: a 1,000,000-second request
    returned allowed=True with reason ``'ok'`` and the compute budget was
    disabled outright, while reporting success.
    """
    from clayseal.capabilities.compute_budget import ComputeBudgetConfig

    with pytest.raises(ValueError):
        ComputeBudgetConfig(tracked={TOOL: "p"}, ceilings={"p": ceiling})


def test_valid_ceilings_are_still_accepted_on_every_rung():
    from clayseal.capabilities.call_budget import CallBudgetConfig
    from clayseal.capabilities.compute_budget import ComputeBudgetConfig

    ValueBudgetConfig(tracked={TOOL: ("amount", "p")}, ceilings={"p": Decimal(10)})
    ValueBudgetConfig(ceilings={"p": None})            # None means "no ceiling"
    CallBudgetConfig(tracked={TOOL: "p"}, ceilings={"p": 10})
    ComputeBudgetConfig(tracked={TOOL: "p"}, ceilings={"p": 30.0})
