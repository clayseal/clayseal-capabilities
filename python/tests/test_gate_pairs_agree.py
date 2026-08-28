"""Every budget exposes two gates. They have to answer the same question alike.

`would_allow` answers "would this be allowed" without side effects, and
`reserve` answers it while holding the amount under the same lock. They are
alternatives: a caller picks one, and the library cannot tell which. If they
disagree, some fraction of integrations get the wrong answer and nothing
notices, because each gate has its own passing tests.

They did disagree. `PrincipalBudgetView.reserve` read an undeclared `config`
attribute and returned `ok_untracked` whenever it was unset, admitting 20 of 20
calls of 10.00 against a ceiling of 100 while `would_allow` on the same object
correctly admitted 10. That was the third instance in this repository of one
question having two implementations where the disagreeing one failed open; the
two path matchers and the egress host parse were the others.

So this checks the property rather than the instance. At every step of a
sequence, ask `would_allow`, then `reserve`, and require the same verdict. A new
budget with the same shape is covered by adding one line to CASES.
"""
from __future__ import annotations

from decimal import Decimal

import pytest

from clayseal.capabilities.call_budget import CallBudgetConfig, SessionCallBudget
from clayseal.capabilities.compute_budget import ComputeBudgetConfig, SessionComputeBudget
from clayseal.capabilities.principal_ledger import PrincipalBudgetView, PrincipalLedger
from clayseal.capabilities.value_budget import SessionValueBudget, ValueBudgetConfig
from clayseal.capabilities.windowed_budget import WindowedValueBudget

TRACKED = {"pay": ("amount", "spend")}
ARGS = {"amount": "10.00"}
ATTEMPTS = 25
#: Ten calls of 10.00 fit under a ceiling of 100; the remaining fifteen do not.
EXPECTED_ADMITTED = 10


def _value():
    return SessionValueBudget(config=ValueBudgetConfig(
        tracked=TRACKED, ceilings={"spend": "100.00"}))


def _windowed():
    return WindowedValueBudget(config=ValueBudgetConfig(
        tracked=TRACKED, ceilings={"spend": "100.00"}))


def _principal():
    return PrincipalBudgetView(
        ledger=PrincipalLedger(), principal="agent-1",
        ceilings={"spend": Decimal("100.00")}, tracked=TRACKED, session="s1")


def _calls():
    # A call budget maps tool -> budget_id directly: one call is one unit. It
    # does NOT take the value budget's (amount_arg, budget_id) tuple.
    return SessionCallBudget(config=CallBudgetConfig(
        tracked={"pay": "spend"}, ceilings={"spend": 10}))


def _compute():
    # Ten calls of 10 seconds against a 100-second ceiling, to keep the
    # arithmetic the same as every other case here.
    return SessionComputeBudget(config=ComputeBudgetConfig(
        tracked={"pay": "cpu"}, ceilings={"cpu": 100.0}))


def _ask(budget, compute: bool):
    """(`would_allow` verdict, `reserve` result) for the next call."""
    if compute:
        ok, _reason = budget.would_allow("pay", 10.0)
        return ok, budget.reserve("pay", 10.0)
    ok, _reason = budget.would_allow("pay", ARGS)
    return ok, budget.reserve("pay", ARGS)


def _run(make, *, compute: bool = False):
    """Drive a sequence, checking both gates agree at every step.

    Returns how many calls were admitted, so a caller can also assert the
    ceiling was the right size rather than merely consistently wrong.
    """
    budget, admitted, disagreements = make(), 0, []
    for step in range(ATTEMPTS):
        predicted, res = _ask(budget, compute)
        if predicted != res.allowed:
            disagreements.append((step, predicted, res.allowed, res.reason))
        if res.allowed:
            admitted += 1
            res.commit()
        elif hasattr(res, "release"):
            res.release()
    return admitted, disagreements


CASES = [
    ("SessionValueBudget", _value, False),
    ("WindowedValueBudget", _windowed, False),
    ("PrincipalBudgetView", _principal, False),
    ("SessionCallBudget", _calls, False),
    ("SessionComputeBudget", _compute, True),
]


@pytest.mark.parametrize("name,make,compute", CASES, ids=[c[0] for c in CASES])
def test_the_two_gates_never_disagree(name, make, compute):
    _admitted, disagreements = _run(make, compute=compute)
    assert not disagreements, (
        f"{name}: would_allow and reserve disagreed at "
        f"{[(s, f'would_allow={p}', f'reserve={a}', r) for s, p, a, r in disagreements]}. "
        "One of these gates is not enforcing the ceiling."
    )


@pytest.mark.parametrize("name,make,compute", CASES, ids=[c[0] for c in CASES])
def test_the_ceiling_is_the_size_it_was_declared(name, make, compute):
    """Agreement alone is satisfiable by two gates that both allow everything."""
    admitted, _ = _run(make, compute=compute)
    assert admitted == EXPECTED_ADMITTED, (
        f"{name}: admitted {admitted} of {ATTEMPTS}, expected {EXPECTED_ADMITTED}")


def test_the_harness_can_tell_a_disagreement_from_agreement():
    """The control.

    Every assertion above is satisfied by a harness that never actually calls
    the second gate. Force a known disagreement and require it to be seen.
    """
    class Rigged(SessionValueBudget):
        def would_allow(self, tool_name, args):   # never refuses
            return True, "rigged"

    def make():
        return Rigged(config=ValueBudgetConfig(
            tracked=TRACKED, ceilings={"spend": "100.00"}))

    admitted, disagreements = _run(make)
    assert disagreements, "the harness did not notice a gate that always allows"
    assert admitted == EXPECTED_ADMITTED, admitted
