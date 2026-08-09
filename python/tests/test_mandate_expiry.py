"""Mandate expiry: a control that shipped and was enforced nowhere.

Every mandate schema carries `expires_at`. Thirteen benchmark loaders write one.
`compile_task_scope` discarded it, `TaskScope` had no field for it, and the
broker allowed actions under a grant that expired four hundred days earlier,
returning ALLOW with an empty reason list.

An expiry nobody reads is not a control, and this is the whole of what these
tests are for.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agentauth.capabilities.broker import Outcome, SessionBroker
from agentauth.capabilities.monitor import Action
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.core.task_scope import compile_task_scope

PAST = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
FUTURE = (datetime.now(timezone.utc) + timedelta(days=400)).isoformat()


def _scope(expires_at: str | None):
    mandate = {
        "grant_id": "g", "issuer": "did:x", "issued_at": PAST,
        "allowed_actions": ["read"], "allowed_resources": ["mcp:tool:t"],
    }
    if expires_at is not None:
        mandate["expires_at"] = expires_at
    return compile_task_scope(mandate)


def _authorize(scope, **kw):
    broker = SessionBroker(goal=GoalSpec(query_id="q", summary="s"), scope=scope, **kw)
    decision = broker.authorize(Action(
        step=0, tool="t", resource="mcp:tool:t", verb="read", args={}))
    return broker, decision


# --------------------------------------------------------------------------- #
# The compiled scope has to carry it at all
# --------------------------------------------------------------------------- #
def test_the_compiled_scope_keeps_the_expiry():
    assert _scope(FUTURE).expires_at is not None


def test_an_expired_scope_knows_it():
    assert _scope(PAST).is_expired()
    assert not _scope(FUTURE).is_expired()


def test_no_expiry_never_expires():
    """A scope written before this field existed must behave as it did.

    Uses the human-authorization schema, because the mandate schema REQUIRES an
    expiry and refuses to parse without one, which is the stronger guarantee.
    """
    scope = compile_task_scope({
        "mandate_id": "m", "scope": {"allowed_paths": ["/app/**"]}})
    assert scope.expires_at is None
    assert not scope.is_expired()


def test_the_mandate_schema_refuses_a_document_with_no_expiry():
    with pytest.raises((KeyError, ValueError)):
        compile_task_scope({
            "grant_id": "g", "issuer": "did:x", "issued_at": PAST,
            "allowed_actions": ["read"], "allowed_resources": ["mcp:tool:t"]})


def test_expiry_is_evaluated_against_an_injectable_moment():
    scope = _scope(FUTURE)
    assert not scope.is_expired(datetime.now(timezone.utc))
    assert scope.is_expired(datetime.now(timezone.utc) + timedelta(days=500))


def test_a_naive_timestamp_is_treated_as_utc_rather_than_crashing():
    scope = compile_task_scope({
        "mandate_id": "m", "scope": {"allowed_paths": ["/app/**"]},
        "expires_at": "2020-01-01T00:00:00",
    })
    assert scope.is_expired()


# --------------------------------------------------------------------------- #
# And the broker has to act on it
# --------------------------------------------------------------------------- #
def test_an_expired_grant_authorizes_nothing():
    _, decision = _authorize(_scope(PAST))
    assert decision.outcome is Outcome.DENY
    assert "expired" in decision.reasons[0]


def test_a_valid_grant_is_unaffected():
    _, decision = _authorize(_scope(FUTURE))
    assert decision.outcome is Outcome.ALLOW


def test_expiry_is_a_hard_denial_not_a_step_up():
    """An expired grant is not uncertainty about scope, it is the absence of
    authority, and no amount of human confirmation at the step-up prompt creates
    a grant. The answer is to issue a new one."""
    _, decision = _authorize(_scope(PAST), graduated=True)
    assert decision.outcome is Outcome.DENY


def test_expiry_precedes_every_other_check():
    """An expired grant must not be able to reach scope, egress or budgets, so
    the reason is always the expiry rather than whatever else was also wrong."""
    scope = _scope(PAST)
    broker = SessionBroker(goal=GoalSpec(query_id="q", summary="s"), scope=scope)
    decision = broker.authorize(Action(
        step=0, tool="other", resource="mcp:tool:not-granted",
        verb="delete", args={"file_path": "/home/u/.ssh/id_rsa"}))
    assert decision.outcome is Outcome.DENY
    assert "expired" in decision.reasons[0]


def test_the_refusal_is_counted():
    broker, _ = _authorize(_scope(PAST))
    assert broker.metrics.prevented_expired_grants == 1


def test_a_grant_expiring_mid_session_stops_authorizing():
    """The case an expiry exists for: a long session that outlives its grant."""
    moment = datetime.now(timezone.utc)
    scope = compile_task_scope({
        "grant_id": "g", "issuer": "did:x", "issued_at": PAST,
        "expires_at": (moment + timedelta(seconds=30)).isoformat(),
        "allowed_actions": ["read"], "allowed_resources": ["mcp:tool:t"],
    })
    clock = {"now": moment}
    broker = SessionBroker(goal=GoalSpec(query_id="q", summary="s"), scope=scope,
                           clock=lambda: clock["now"])
    act = Action(step=0, tool="t", resource="mcp:tool:t", verb="read", args={})
    assert broker.authorize(act).outcome is Outcome.ALLOW
    clock["now"] = moment + timedelta(minutes=5)
    assert broker.authorize(act).outcome is Outcome.DENY
