"""The audit budget: human attention as a finite, spendable resource.

Two reasons this exists, and the second is the one that matters.

The obvious one is honesty in reporting. A configuration that reaches baseline
utility by asking for 0.72 confirmations per task is not free, and until now
nothing in the system charged for those confirmations.

The load-bearing one is security. A step-up policy is attackable by exhaustion:
issue enough plausible confirmations and the human stops reading them. An
unbounded step-up count is therefore an unbounded attack surface, and bounding
it turns "keep asking forever" into an explicit decision about what to do when
the attention runs out.
"""
from __future__ import annotations

import pytest

from agentauth.capabilities.broker import Outcome, SessionBroker
from agentauth.capabilities.monitor import Action
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.core.task_scope import TaskScope


def _broker(**kw) -> SessionBroker:
    """A broker whose scope forces a soft miss, which is a step-up path."""
    goal = GoalSpec(query_id="q1", summary="summarize the workspace notes")
    scope = TaskScope(allowed_resources=["mcp:tool:read_file"], allowed_actions=[])
    return SessionBroker(goal=goal, scope=scope, **kw)


def _action(step: int, tool: str = "send_email") -> Action:
    return Action(step=step, tool=tool, resource=f"mcp:tool:{tool}",
                  verb="send", args={"body": "hello"})


def test_unlimited_by_default():
    """Default must not change existing measurements."""
    broker = _broker()
    assert broker.audit_budget is None
    outcomes = [broker.authorize(_action(i)).outcome for i in range(6)]
    assert all(o is Outcome.STEP_UP for o in outcomes)
    assert broker.audits_spent == 0  # nothing charged when there is no budget


def test_step_ups_are_charged_against_the_budget():
    broker = _broker(audit_budget=2)
    assert broker.authorize(_action(0)).outcome is Outcome.STEP_UP
    assert broker.authorize(_action(1)).outcome is Outcome.STEP_UP
    assert broker.audits_spent == 2


def test_exhausted_budget_denies_by_default():
    """Conservative default: no attention left means no, not yes."""
    broker = _broker(audit_budget=1)
    assert broker.authorize(_action(0)).outcome is Outcome.STEP_UP
    decision = broker.authorize(_action(1))
    assert decision.outcome is Outcome.DENY
    assert any("audit budget exhausted" in r for r in decision.reasons)
    assert decision.step_up is None


def test_exhausted_budget_can_be_configured_to_allow():
    """The other side of the trade, which must never be the default."""
    broker = _broker(audit_budget=1, on_audit_exhausted="allow")
    assert broker.authorize(_action(0)).outcome is Outcome.STEP_UP
    decision = broker.authorize(_action(1))
    assert decision.outcome is Outcome.ALLOW
    assert any("audit budget exhausted" in r for r in decision.reasons)


def test_budget_does_not_charge_allows_or_denies():
    """Only interruptions cost attention."""
    broker = _broker(audit_budget=5)
    allowed = broker.authorize(Action(step=0, tool="read_file",
                                      resource="mcp:tool:read_file", verb="read", args={}))
    assert allowed.outcome is Outcome.ALLOW
    assert broker.audits_spent == 0


def test_exhaustion_is_recorded_on_the_decision_log():
    """An operator has to be able to see that the system stopped asking."""
    broker = _broker(audit_budget=1)
    broker.authorize(_action(0))
    broker.authorize(_action(1))
    reasons = [
        " ".join(r.get("decision", {}).get("reasons", ()))
        for r in broker.decision_log.records()
    ]
    assert any("audit budget exhausted" in r for r in reasons), reasons


@pytest.mark.parametrize("budget", [0, 1, 3])
def test_step_ups_never_exceed_the_budget(budget):
    """The property the whole thing exists to guarantee."""
    broker = _broker(audit_budget=budget)
    step_ups = sum(
        1 for i in range(10) if broker.authorize(_action(i)).outcome is Outcome.STEP_UP
    )
    assert step_ups <= budget
