"""The delegation boundary, wired into the live floor.

`deputy.DelegationBoundary` contained 100% of sub-agent overreach in the
benchmark and had no runtime input: it read a principal that nothing populated.
Any orchestrator knows which sub-agent issued a call, so the gap was plumbing
rather than information. These tests assert the plumbing, and the one that
matters most is the pass-through: a single-principal session must be unchanged.
"""
from __future__ import annotations

import pytest

from clayseal.capabilities.broker import Outcome, SessionBroker
from clayseal.capabilities.monitor import Action
from clayseal.capabilities.scoping.goal import GoalSpec
from clayseal.core.task_scope import TaskScope


class _Boundary:
    """Stands in for DelegationBoundary: only `authorize` is contracted."""

    def __init__(self, allow_for: set[str]):
        self.allow_for = allow_for
        self.seen: list[str] = []

    def authorize(self, *, principal, resource, action, envelope):
        from clayseal.capabilities.deputy import PrincipalVerdict

        self.seen.append(principal)
        if envelope is None:
            return PrincipalVerdict(False, f"no delegation presented by {principal!r}",
                                    "presented")
        if principal in self.allow_for:
            return PrincipalVerdict(True, "within the delegated sub-scope", "scope")
        return PrincipalVerdict(False, "outside the delegated sub-scope", "scope")


def _broker(**kw):
    return SessionBroker(
        goal=GoalSpec(query_id="q", summary="summarise the inbox"),
        scope=TaskScope(allowed_resources=["mcp:tool:read_email"], allowed_actions=[]),
        **kw)


def _act(principal=None):
    meta = {"principal": principal} if principal else {}
    return Action(step=0, tool="read_email", resource="mcp:tool:read_email",
                  verb="read", args={}, meta=meta)


def test_a_single_principal_session_is_unchanged():
    """The property that lets this ship: no delegation configured, no behaviour
    change, so every existing number stands."""
    assert _broker().authorize(_act()).outcome is Outcome.ALLOW


def test_the_delegated_sub_agent_may_act_inside_its_sub_scope():
    boundary = _Boundary(allow_for={"sub"})
    broker = _broker(delegation=boundary,
                     delegation_envelopes={"sub": {"token": "..."}})
    assert broker.authorize(_act("sub")).outcome is Outcome.ALLOW
    assert boundary.seen == ["sub"]


def test_a_sub_agent_outside_its_sub_scope_is_refused_inside_the_mandate():
    """The whole point. The action is in the session's scope, and the principal's
    own chain does not carry it."""
    broker = _broker(delegation=_Boundary(allow_for={"other"}),
                     delegation_envelopes={"sub": {"token": "..."}})
    decision = broker.authorize(_act("sub"))
    assert decision.outcome is Outcome.DENY
    assert "sub-scope" in decision.reasons[0]


def test_an_unattributed_action_fails_closed_in_a_delegating_session():
    """An action nobody signed for is the confused deputy's best disguise."""
    broker = _broker(delegation=_Boundary(allow_for={"sub"}))
    decision = broker.authorize(_act())
    assert decision.outcome is Outcome.DENY
    assert "no acting principal" in decision.reasons[0]


def test_presenting_no_credential_is_refused():
    """Silence was the attacker's best presentation against the shipped
    primitive: `verify_delegation_chain(None)` returned no violations."""
    broker = _broker(delegation=_Boundary(allow_for={"sub"}), delegation_envelopes={})
    assert broker.authorize(_act("sub")).outcome is Outcome.DENY


def test_the_refusal_is_counted():
    broker = _broker(delegation=_Boundary(allow_for={"other"}),
                     delegation_envelopes={"sub": {"token": "..."}})
    broker.authorize(_act("sub"))
    assert broker.metrics.prevented_delegation_overreach == 1


def test_whose_authority_is_asked_before_where_it_points():
    """An overreaching principal must not be able to reach scope, egress or
    budgets, so the reason names the principal rather than whatever else was
    also wrong."""
    broker = _broker(delegation=_Boundary(allow_for={"other"}),
                     delegation_envelopes={"sub": {"token": "..."}})
    decision = broker.authorize(Action(
        step=0, tool="write_file", resource="mcp:tool:not-granted", verb="delete",
        args={"file_path": "/home/u/.ssh/id_rsa"}, meta={"principal": "sub"}))
    assert decision.outcome is Outcome.DENY
    assert "sub-scope" in decision.reasons[0]
