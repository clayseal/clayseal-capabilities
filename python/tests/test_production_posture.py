"""Every signed object in this layer must fail closed in production, the same way.

`verify_commit_token` has refused an unpinned minter in production for a while.
Writing the threat model surfaced that the other two signed objects did not, and
both gaps are the shape this repository already names in `principal_ledger`: "a
control that stopped applying when its input was unusual, and reported success."

**The intent envelope** accepted any keyholder when `trusted_keys` was unset. It
is the object `SessionBroker.reclear` swaps mid-session — the supported way a
running session's plan is WIDENED — so a self-signed envelope replaced the sealed
plan wholesale, and every later conformance check then measured the agent against
the attacker's plan.

**The step-up approval** honoured `AGENTAUTH_STEP_UP_ALLOW_UNSIGNED=1` in
production. An approval is the one object in the protocol whose whole job is to
grant something the floor refused, and one environment variable turned off its
authentication. Its siblings were already in the production deny-list; this one
was not.

These tests exist so the three objects cannot drift apart again.
"""
from __future__ import annotations

import pytest

from agentauth.capabilities.commit import issue_commit_token, verify_commit_token
from agentauth.capabilities.monitor.intent_envelope import (
    IntentEnvelope,
    sign_intent_envelope,
    verify_intent_envelope,
)
from agentauth.capabilities.step_up import (
    ALLOW_UNSIGNED_ENV,
    StepUpApproval,
    apply_step_up,
    bind_to_action,
    build_step_up_request,
    sign_step_up_approval,
)
from agentauth.core.runtime import (
    ActionDescriptor,
    AuthorityContext,
    ExecutionContext,
)
from agentauth.core.signing import generate_keypair


@pytest.fixture
def production(monkeypatch):
    monkeypatch.setenv("AGENTAUTH_ENV", "production")


def _envelope():
    return IntentEnvelope(
        allowed_tools=frozenset({"anything"}),
        allowed_verbs=frozenset(),
        allowed_resource_classes=frozenset(),
    )


def _ctx():
    return ExecutionContext(
        action=ActionDescriptor(action_name="t/call/pay", resource_ref="acct:1"),
        input={"amount": 10},
        authority=AuthorityContext(authority_id="a"),
        query_id="q",
    )


def _request():
    return bind_to_action(
        build_step_up_request(
            request_id="r", query_id="q", resource_ref="mcp:tool:pay",
            operation="send",
            violations=["egress to 'novel.test' not on allow-list"],
        ),
        tool="pay", arguments_hash="sha256:h", layer="floor",
    )


# --------------------------------------------------------------------------- #
# The envelope.
# --------------------------------------------------------------------------- #
def test_an_unpinned_envelope_is_refused_in_production(production):
    """A signature proves integrity, not authority."""
    signed = sign_intent_envelope(_envelope(), key=generate_keypair())
    ok, reason = verify_intent_envelope(signed)
    assert not ok
    assert "trusted control-plane keys required in production" in reason


def test_a_pinned_envelope_is_accepted_in_production(production):
    key = generate_keypair()
    signed = sign_intent_envelope(_envelope(), key=key)
    assert verify_intent_envelope(signed, trusted_keys={key.public_key_hex}) == (
        True, None
    )


def test_an_envelope_from_the_wrong_signer_is_refused_even_when_pinned(production):
    """The attack the pin exists for: a valid signature from the wrong keyholder."""
    attacker = generate_keypair()
    operator = generate_keypair()
    signed = sign_intent_envelope(_envelope(), key=attacker)
    ok, reason = verify_intent_envelope(signed, trusted_keys={operator.public_key_hex})
    assert not ok
    assert "not a trusted control-plane key" in reason


def test_reclear_refuses_an_unpinned_envelope_in_production(production):
    """The entry point that made the gap consequential.

    `reclear` is how a session adopts a NEW plan mid-flight. Accepting one from
    any keyholder means an attacker who reaches it replaces the sealed goal's
    plan, and every later conformance check measures against theirs.
    """
    from agentauth.capabilities.broker import SessionBroker
    from agentauth.capabilities.scoping.goal import GoalSpec

    broker = SessionBroker(goal=GoalSpec(query_id="q", summary="pay invoices"))
    before = broker.intent_envelope
    forged = sign_intent_envelope(_envelope(), key=generate_keypair())

    assert broker.reclear(signed=forged) is False
    assert broker.intent_envelope is before

    # And the refusal is on the audit chain, not silent.
    records = broker.decision_log.records()
    assert any(r["action"]["tool"] == "<reclearance>" for r in records)
    assert any(r["decision"]["outcome"] == "deny" for r in records)


def test_development_still_accepts_an_unpinned_envelope(monkeypatch):
    """The guard is about production, not about making local work impossible."""
    monkeypatch.delenv("AGENTAUTH_ENV", raising=False)
    monkeypatch.delenv("AGENT_RECEIPTS_ENV", raising=False)
    signed = sign_intent_envelope(_envelope(), key=generate_keypair())
    assert verify_intent_envelope(signed) == (True, None)


# --------------------------------------------------------------------------- #
# The step-up approval.
# --------------------------------------------------------------------------- #
def test_the_unsigned_escape_is_refused_in_production(production, monkeypatch):
    monkeypatch.setenv(ALLOW_UNSIGNED_ENV, "1")
    request = _request()
    unsigned = StepUpApproval(
        approval_id="a", request_commitment=request.commitment(),
        allow_resources=["mcp:tool:pay"], allow_write=True,
    )
    authority = AuthorityContext(authority_id="t", authority_version=1)

    with pytest.raises(ValueError, match="refused in production"):
        apply_step_up(authority, unsigned, request_commitment=request.commitment())

    # Nothing was widened on the way to the refusal.
    assert authority.resource_scope == []
    assert authority.authority_version == 1


def test_the_explicit_unsigned_argument_is_also_refused_in_production(production):
    """`allow_unsigned=True` is the same fail-open with a different spelling."""
    request = _request()
    unsigned = StepUpApproval(
        approval_id="a", request_commitment=request.commitment(),
        allow_resources=["mcp:tool:pay"], allow_write=True,
    )
    with pytest.raises(ValueError, match="refused in production"):
        apply_step_up(
            AuthorityContext(authority_id="t"), unsigned,
            request_commitment=request.commitment(), allow_unsigned=True,
        )


def test_a_signed_approval_still_applies_in_production(production):
    """The guard refuses unsigned approvals, not supervision itself."""
    key = generate_keypair()
    request = _request()
    signed = sign_step_up_approval(
        StepUpApproval(
            approval_id="a", request_commitment=request.commitment(),
            allow_resources=["mcp:tool:pay"], allow_write=True,
        ),
        key=key,
    )
    authority = AuthorityContext(authority_id="t", authority_version=1)
    apply_step_up(authority, signed, request_commitment=request.commitment())
    assert "mcp:tool:pay" in authority.resource_scope


# --------------------------------------------------------------------------- #
# The contract the three share.
# --------------------------------------------------------------------------- #
def test_the_commit_token_posture_is_unchanged(production):
    """The control the other two were measured against."""
    ctx = _ctx()
    token = issue_commit_token(ctx, key=generate_keypair(), ttl_seconds=300)
    ok, reason = verify_commit_token(token, ctx=ctx)
    assert not ok
    assert "trusted minting keys required in production" in reason


def test_every_signed_object_fails_closed_on_an_unpinned_signer(production):
    """One table, so a fourth signed object cannot be added without this question.

    Each entry is (what it is, does an unpinned signer get through). All three
    must be False; two of them were True before the threat-model pass.
    """
    ctx = _ctx()
    outcomes = {
        "commit_token": verify_commit_token(
            issue_commit_token(ctx, key=generate_keypair(), ttl_seconds=300), ctx=ctx
        )[0],
        "intent_envelope": verify_intent_envelope(
            sign_intent_envelope(_envelope(), key=generate_keypair())
        )[0],
    }
    assert outcomes == {"commit_token": False, "intent_envelope": False}
