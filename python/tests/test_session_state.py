"""A session has to survive leaving the process it was created in.

`SessionBroker` kept every control it accumulates in object memory and nowhere
else. The one that matters most is the outstanding step-up: `resolve_step_up`
refuses any approval whose commitment "this session never issued", which is the
right check and means the protocol cannot complete when the worker that receives
the human's answer is not the worker that asked. On a single instance that is
invisible; behind a load balancer it is the whole feature.

These tests exercise the round trip through JSON, not through pickle or a live
object, because that is what a store actually holds.
"""
from __future__ import annotations

import json

import pytest

from agentauth.capabilities.broker import Outcome, SessionBroker
from agentauth.capabilities.monitor.action import Action, ContextItem, TrustLevel
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.capabilities.session_state import (
    SESSION_STATE_SCHEMA,
    restore,
    snapshot,
)
from agentauth.core.task_scope import TaskScope

GOAL = GoalSpec(query_id="q-1", summary="pay the approved invoices")
SCOPE = TaskScope(
    allowed_resources=["in-scope"],
    allowed_actions=["read", "write", "send"],
)


def _fresh() -> SessionBroker:
    """A broker rebuilt from CONFIGURATION, the way a second worker would."""
    return SessionBroker(goal=GOAL, scope=SCOPE)


def _round_trip(broker: SessionBroker) -> SessionBroker:
    state = json.loads(json.dumps(snapshot(broker)))
    revived = _fresh()
    restore(revived, state)
    return revived


def test_the_snapshot_is_json_serialisable():
    broker = _fresh()
    broker.authorize(Action(0, "tool", "in-scope", "read", args={"n": 1}))
    encoded = json.dumps(snapshot(broker))
    assert json.loads(encoded)["schema"] == SESSION_STATE_SCHEMA


def test_a_step_up_asked_on_one_worker_resolves_on_another():
    """The finding this module exists for."""
    from agentauth.capabilities.step_up import (
        StepUpApproval,
        bind_to_action,
        build_step_up_request,
        sign_step_up_approval,
    )
    from agentauth.core.signing import generate_keypair

    asking = _fresh()
    request = bind_to_action(
        build_step_up_request(
            request_id="r1", query_id="q-1",
            resource_ref="mcp:tool:send_money", operation="send",
            violations=["egress to 'novel.test' not on allow-list"],
        ),
        tool="send_money", arguments_hash="sha256:aaa", layer="floor",
    )
    asking._pending[request.commitment()] = request

    answering = _round_trip(asking)

    approval = sign_step_up_approval(
        StepUpApproval(
            approval_id="a-1",
            request_commitment=request.commitment(),
            allow_resources=["mcp:tool:send_money"],
            allow_write=True,
        ),
        key=generate_keypair(),
    )
    ok, reason = answering.resolve_step_up(approval)
    assert ok, reason
    assert answering.grants.waives(
        tool="send_money", arguments_hash="sha256:aaa", code=request.codes[0]
    )


def test_the_request_survives_a_round_trip_byte_for_byte():
    """`from_dict(to_dict(r))` must commit to the same bytes.

    The commitment is a hash over every field. A field added to `to_dict` and
    forgotten in `from_dict` changes the commitment silently, and every approval
    in flight stops matching the request it answers.
    """
    from agentauth.capabilities.step_up import (
        StepUpRequest,
        bind_to_action,
        build_step_up_request,
    )

    request = bind_to_action(
        build_step_up_request(
            request_id="r1", query_id="q-1", resource_ref="mcp:tool:pay",
            operation="send", violations=["egress to 'x.test' not on allow-list"],
        ),
        tool="pay", arguments_hash="sha256:bbb", layer="floor",
    )
    revived = StepUpRequest.from_dict(json.loads(json.dumps(request.to_dict())))
    assert revived.commitment() == request.commitment()
    assert revived == request


def test_spent_approvals_and_audit_spend_survive_a_restart():
    """Both are ceilings. A ceiling that resets on restart is not a ceiling."""
    broker = SessionBroker(goal=GOAL, scope=SCOPE, audit_budget=2)
    broker.authorize(Action(0, "tool", "out-of-scope", "write", args={"n": 0}))
    broker._consumed.add("approval-already-spent")

    revived = _round_trip(broker)
    assert revived.audits_spent == broker.audits_spent == 1
    assert "approval-already-spent" in revived._consumed


def test_the_trajectory_and_its_context_survive():
    broker = _fresh()
    broker.observe_context(
        ContextItem(item_id="doc-1", trust=TrustLevel.UNTRUSTED, summary="an invoice")
    )
    broker.authorize(Action(0, "tool", "in-scope", "read", args={"n": 1}))

    revived = _round_trip(broker)
    assert [a.resource for a in revived._trajectory.actions] == ["in-scope"]
    assert [c.item_id for c in revived._trajectory.context] == ["doc-1"]
    assert revived._trajectory.context[0].trust is TrustLevel.UNTRUSTED


def test_the_audit_chain_continues_rather_than_forking():
    """A rehydrated session appends to the chain it already had.

    Starting a second chain would leave a verifier with two logs and no way to
    order them, which is the same evidence gap as having no log for the gap.
    """
    broker = _fresh()
    for i in range(3):
        broker.authorize(Action(i, "tool", "in-scope", "read", args={"n": i}))
    head = broker.decision_log.head_hash

    revived = _round_trip(broker)
    assert revived.decision_log.session_id == broker.decision_log.session_id
    assert revived.decision_log.head_hash == head

    revived.authorize(Action(3, "tool", "in-scope", "read", args={"n": 3}))
    ok, reason = revived.decision_log.verify()
    assert ok, reason
    records = revived.decision_log.records()
    assert len(records) == 4
    assert records[3]["prev_hash"] == head


def test_a_tampered_chain_is_refused_rather_than_adopted():
    """A tamper-evident log a restore can rewrite is not tamper-evident."""
    broker = _fresh()
    for i in range(3):
        broker.authorize(Action(i, "tool", "in-scope", "write", args={"n": i}))

    state = json.loads(json.dumps(snapshot(broker)))
    # Rewrite a past decision the way an attacker with store access would: turn
    # a refusal into a pass, or point a recorded action at a different tool.
    assert state["decision_log"]["records"][1]["action"]["tool"] == "tool"
    state["decision_log"]["records"][1]["action"]["tool"] = "some_other_tool"

    revived = _fresh()
    with pytest.raises(ValueError, match="decision chain does not verify"):
        restore(revived, state)
    # And it did not half-adopt the bad chain.
    assert revived.decision_log.records() == []


def test_state_for_a_different_query_is_refused():
    """A snapshot is not a channel for moving authority between sessions."""
    broker = _fresh()
    broker.authorize(Action(0, "tool", "in-scope", "read", args={"n": 1}))
    state = snapshot(broker)
    state["query_id"] = "someone-elses-session"

    with pytest.raises(ValueError, match="is for query"):
        restore(_fresh(), state)


def test_a_foreign_schema_is_refused():
    with pytest.raises(ValueError, match="schema"):
        restore(_fresh(), {"schema": "something.else.v9", "query_id": "q-1"})
    with pytest.raises(TypeError):
        restore(_fresh(), ["not", "an", "object"])


def test_an_expired_grant_is_restored_expired():
    """Round-tripping must not restart the clock on authority a human gave."""
    from agentauth.capabilities.session_grants import GrantSource

    broker = _fresh()
    broker.grants.grant_one_shot(
        tool="pay", arguments_hash="sha256:ccc", waived_codes=["egress"],
        source=GrantSource.HUMAN, ttl_seconds=-1,
    )
    revived = _round_trip(broker)
    assert not revived.grants.waives(
        tool="pay", arguments_hash="sha256:ccc", code="egress"
    )


def test_configuration_is_deliberately_not_carried():
    """Only what a session ACCUMULATES travels; the mandate is rebuilt.

    A snapshot carrying the scope would let a restore widen authority, so the
    keys below must never appear in one.
    """
    broker = _fresh()
    broker.authorize(Action(0, "tool", "in-scope", "read", args={"n": 1}))
    state = snapshot(broker)
    for forbidden in ("scope", "egress", "capabilities", "allowed_tools",
                      "value_budget", "call_budget", "intent_envelope"):
        assert forbidden not in state, forbidden
