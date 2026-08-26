"""A ceiling that survives where no session does.

MCP 2026-07-28 removes the `initialize` handshake and the `Mcp-Session-Id`
header so any instance can serve any request without sticky routing. A ceiling
counted per session then counts over nothing: it resets on every call and the
aggregate rung this library exists for is inert. These tests hold the
substitution that fixes it, and the two properties that have to survive a
PROCESS boundary rather than only a session one.
"""
from __future__ import annotations

from decimal import Decimal

import pytest

from agentauth.capabilities.monitor.action import Action
from agentauth.capabilities.policy import PolicyError, load_policy_text
from agentauth.capabilities.principal_ledger import PrincipalLedger

BUDGET = """
budgets:
  value:
    ceilings: {payments: "50000"}
    tracked: {pay_vendor: {arg: amount, budget: payments, identity: [invoice]}}
"""
BASE = """
version: 1
goal: {id: ap, summary: Pay approved invoices}
profile: supervised
tools: {allow: [pay_vendor], effects: {pay_vendor: transfer}}
""" + BUDGET


def _document(path) -> str:
    return BASE + (f"deployment: {{stateless: true, principal: acct-9, "
                   f"ledger: {{path: {path}}}}}\n")


def _pay(stack, step, amount, invoice):
    return stack.authorize(Action(
        step=step, tool="pay_vendor", resource="mcp:tool:pay_vendor",
        verb="transfer", args={"amount": amount, "invoice": invoice}, meta={}))


# ------------------------------------------------------- the substitution ---
def test_a_declared_principal_moves_the_ceiling_off_the_session(tmp_path):
    from agentauth.capabilities.principal_ledger import PrincipalBudgetView

    policy = load_policy_text(_document(tmp_path / "l.jsonl"))
    assert isinstance(policy.value_budget, PrincipalBudgetView)
    assert not [f for f in policy.lint() if f.code == "session-scoped-ceiling"]


def test_a_stateless_deployment_without_a_principal_is_an_error():
    policy = load_policy_text(BASE + "deployment: {stateless: true}\n")
    finding = next(f for f in policy.lint()
                   if f.code == "session-scoped-ceiling")
    assert finding.level == "error"


def test_an_in_memory_ledger_in_a_stateless_deployment_is_refused():
    """It is a session ledger wearing another name: it dies with the process,
    and a stateless deployment is many processes."""
    with pytest.raises(PolicyError, match="durable storage"):
        load_policy_text(BASE + "deployment: {stateless: true, principal: a}\n")


# ------------------------------------ what must survive a process boundary ---
def test_the_ceiling_survives_a_process_boundary(tmp_path):
    document = _document(tmp_path / "l.jsonl")
    first = load_policy_text(document).build()
    assert _pay(first, 1, "30000", "INV-1").outcome == "allow"
    assert _pay(first, 2, "15000", "INV-2").outcome == "allow"

    # A different instance, as a load balancer would choose.
    second = load_policy_text(document).build()
    over = _pay(second, 1, "10000", "INV-3")
    assert over.outcome == "deny"
    assert "value_budget_exceeded" in over.reasons
    assert _pay(second, 2, "4000", "INV-4").outcome == "allow"


def test_once_per_object_survives_a_process_boundary(tmp_path):
    """The more specific half of the same escape.

    The first version of this persisted spend and not identity, so the ceiling
    survived the boundary and the duplicate check did not: a second process
    paid INV-1 again. A ceiling answers "is the total under the limit" and
    answers it correctly while the same invoice is paid twice.
    """
    document = _document(tmp_path / "l.jsonl")
    first = load_policy_text(document).build()
    assert _pay(first, 1, "30000", "INV-1").outcome == "allow"

    second = load_policy_text(document).build()
    again = _pay(second, 1, "1000", "INV-1")
    assert again.outcome == "deny"
    assert "value_budget_duplicate_effect" in again.reasons


def test_a_session_scoped_ceiling_does_not_survive_it(tmp_path):
    """The control. Without this the tests above prove nothing about the fix."""
    document = BASE  # no deployment section: the session budget
    first = load_policy_text(document).build()
    _pay(first, 1, "30000", "INV-1")
    _pay(first, 2, "15000", "INV-2")

    second = load_policy_text(document).build()
    assert _pay(second, 1, "10000", "INV-3").outcome == "allow"
    assert _pay(second, 2, "1000", "INV-1").outcome == "allow"


# ----------------------------------------------- the ledger's own contract ---
def test_a_released_reservation_gives_the_object_back():
    ledger = PrincipalLedger()
    held = ledger.reserve("p", "b", Decimal(10), Decimal(100), identity="INV-1")
    assert held is not None
    assert ledger.reserve("p", "b", Decimal(10), Decimal(100),
                          identity="INV-1") is None
    ledger.release(held)
    assert ledger.reserve("p", "b", Decimal(10), Decimal(100),
                          identity="INV-1") is not None


def test_a_committed_object_is_never_available_again():
    ledger = PrincipalLedger()
    ledger.commit_hold(
        ledger.reserve("p", "b", Decimal(10), Decimal(100), identity="INV-1"))
    assert ledger.reserve("p", "b", Decimal(10), Decimal(100),
                          identity="INV-1") is None
    assert ledger.spent("p", "b") == Decimal(10)


def test_an_unparseable_amount_on_a_tracked_tool_fails_closed(tmp_path):
    """The tri-state `parse_amount` returns is preserved, not flattened.

    Reading a tracked-but-unreadable amount as untracked is the fail-open this
    library already had once, and re-implementing the parse on the principal
    view rather than sharing it is how it would come back.
    """
    stack = load_policy_text(_document(tmp_path / "l.jsonl")).build()
    decision = _pay(stack, 1, "not-a-number", "INV-9")
    assert decision.outcome == "deny"
    assert "value_budget_unparseable_amount" in decision.reasons
