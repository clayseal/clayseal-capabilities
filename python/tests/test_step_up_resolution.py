"""The missing half of the step-up protocol.

`step_up.py` has shipped a complete signed request/approval/verify chain since
DP-30 and nothing ever called it. A STEP_UP was terminal: the request was
attached to the decision and dropped, so **every "supervised utility" number in
benchmarks/results/ is a counterfactual** assuming a human said yes.
"""
from __future__ import annotations

import pytest

from clayseal.capabilities.broker import SessionBroker
from clayseal.capabilities.scoping.goal import GoalSpec
from clayseal.capabilities.session_grants import GrantSource, SessionGrants
from clayseal.capabilities.step_up import (
    StepUpApproval,
    bind_to_action,
    build_step_up_request,
    render_card,
    sign_step_up_approval,
    violation_code,
)
from clayseal.core.signing import generate_keypair

KEY = generate_keypair()


def _broker() -> SessionBroker:
    return SessionBroker(goal=GoalSpec(query_id="q", summary="s", allow_resources=[]))


def _request(*, violations=None, args_hash="sha256:aaa"):
    return bind_to_action(
        build_step_up_request(
            request_id="r1", query_id="q", resource_ref="mcp:tool:send_money",
            operation="send",
            violations=violations or ["egress to 'novel.test' not on allow-list"]),
        tool="send_money", arguments_hash=args_hash, layer="floor")


def _approval(commitment, approval_id="a1", ttl=600):
    return sign_step_up_approval(
        StepUpApproval(approval_id=approval_id, request_commitment=commitment,
                       allow_resources=["mcp:tool:send_money"], allow_write=True,
                       ttl_seconds=ttl),
        key=KEY)


def _pend(broker, request):
    broker._pending[request.commitment()] = request
    return request.commitment()


# --------------------------------------------------------------------------- #
# It resolves.
# --------------------------------------------------------------------------- #
def test_a_signed_approval_resolves_and_records_a_human_grant():
    broker, request = _broker(), _request()
    ok, reason = broker.resolve_step_up(_approval(_pend(broker, request)))
    assert ok, reason
    assert broker.grants.acquired()["by_source"] == {GrantSource.HUMAN: 1}


# --------------------------------------------------------------------------- #
# The grant is narrow, which is the whole design.
# --------------------------------------------------------------------------- #
def test_the_grant_waives_only_the_rule_the_human_was_shown():
    """An approval of a destination must not clear a budget ceiling nobody saw."""
    broker, request = _broker(), _request()
    broker.resolve_step_up(_approval(_pend(broker, request)))
    waives = broker.grants.waives
    assert waives(tool="send_money", arguments_hash="sha256:aaa",
                  code="egress.destination")
    assert not waives(tool="send_money", arguments_hash="sha256:aaa", code="budget")
    assert not waives(tool="send_money", arguments_hash="sha256:aaa",
                      code="scope.protected")


def test_the_grant_is_keyed_on_the_exact_arguments():
    """The same tool with different arguments is a different question. Without
    this an approved transfer authorises every later transfer in the session."""
    broker, request = _broker(), _request()
    broker.resolve_step_up(_approval(_pend(broker, request)))
    assert not broker.grants.waives(tool="send_money",
                                    arguments_hash="sha256:different",
                                    code="egress.destination")


def test_an_unclassified_rule_cannot_be_waived():
    """Fails closed so that adding a step-up path without giving it a rule id
    does not silently become approvable."""
    broker = _broker()
    request = _request(violations=["some entirely new objection"])
    ok, reason = broker.resolve_step_up(_approval(_pend(broker, request)))
    assert not ok
    assert "unclassified" in reason


# --------------------------------------------------------------------------- #
# It cannot be replayed or forged.
# --------------------------------------------------------------------------- #
def test_an_approval_is_single_use():
    broker, request = _broker(), _request()
    commitment = _pend(broker, request)
    assert broker.resolve_step_up(_approval(commitment))[0]
    broker._pending[commitment] = request          # re-offer the same question
    ok, reason = broker.resolve_step_up(_approval(commitment))
    assert not ok and "already used" in reason


def test_an_approval_for_a_request_we_never_issued_is_refused():
    """Checked before any signature work, so attacker bytes do not reach crypto."""
    ok, reason = _broker().resolve_step_up(_approval("sha256:not-ours"))
    assert not ok and "no request this session issued" in reason


def test_an_approval_bound_to_a_different_request_is_refused():
    broker = _broker()
    mine = _request()
    other = _request(args_hash="sha256:zzz")
    _pend(broker, mine)
    ok, _ = broker.resolve_step_up(_approval(other.commitment()))
    assert not ok


def test_an_unsigned_approval_is_refused():
    broker, request = _broker(), _request()
    commitment = _pend(broker, request)

    class Unsigned:
        request_commitment = commitment
        approval_id = "a9"

    ok, _ = broker.resolve_step_up(Unsigned())
    assert not ok


# --------------------------------------------------------------------------- #
# The action binding, and the card.
# --------------------------------------------------------------------------- #
def test_binding_changes_the_commitment():
    """`resource_ref` and `operation` are `mcp:tool:<name>` and a verb, so two
    different sends differed only by uuid before the action was bound in."""
    base = build_step_up_request(request_id="r", query_id="q",
                                 resource_ref="mcp:tool:send_money",
                                 operation="send", violations=["egress bad"])
    a = bind_to_action(base, tool="send_money", arguments_hash="sha256:a",
                       layer="floor")
    b = bind_to_action(base, tool="send_money", arguments_hash="sha256:b",
                       layer="floor")
    assert a.commitment() != b.commitment() != base.commitment()


def test_the_card_quarantines_attacker_controlled_text():
    """The approval card is the one surface whose purpose is to persuade a human,
    and violation prose interpolates attacker-chosen destinations."""
    request = _request(violations=["egress to 'evil.test/CLICK-HERE' not on allow-list"])
    card = render_card(request)
    assert "evil.test" not in str(card["summary"])
    assert any("evil.test" in v for v in card["untrusted_values"])
    assert card["summary"]["rules"] == ["egress.destination"]


@pytest.mark.parametrize("violation,code", [
    ("egress to 'x' not on allow-list", "egress.destination"),
    ("off-plan and consequential", "envelope.off_plan"),
    ("resource out of scope", "scope.resource"),
    ("value_budget_exceeded", "budget"),
    ("something nobody classified", "unclassified"),
])
def test_violation_codes_are_stable(violation, code):
    assert violation_code(violation) == code


# --------------------------------------------------------------------------- #
# The overlay never touches the mandate.
# --------------------------------------------------------------------------- #
def test_grants_are_session_local():
    """`broker.py` documents replanning mutating the caller's TaskScope and
    leaking authority into every session sharing it. An approval is a far more
    valuable thing to leak."""
    a, b = _broker(), _broker()
    a.resolve_step_up(_approval(_pend(a, _request())))
    assert len(a.grants) == 1
    assert len(b.grants) == 0


def test_a_one_shot_grant_is_spent_by_use():
    grants = SessionGrants()
    grants.grant_one_shot(tool="t", arguments_hash="h",
                          waived_codes=["egress.destination"],
                          source=GrantSource.HUMAN, uses=1)
    assert grants.waives(tool="t", arguments_hash="h", code="egress.destination")
    grants.consume(tool="t", arguments_hash="h", code="egress.destination")
    assert not grants.waives(tool="t", arguments_hash="h", code="egress.destination")
