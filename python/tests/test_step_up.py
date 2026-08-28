"""Signed step-up approvals: apply_step_up must authenticate before mutating."""

from __future__ import annotations

import pytest

from clayseal.capabilities.step_up import (
    StepUpApproval,
    apply_step_up,
    build_step_up_request,
    sign_step_up_approval,
    verify_step_up_approval,
)
from clayseal.core.runtime import AuthorityContext
from clayseal.core.signing import generate_keypair


def _request():
    return build_step_up_request(
        request_id="r-1",
        query_id="q-1",
        resource_ref="repo://deploy/prod.yaml",
        operation="write",
        violations=["protected_zone"],
    )


def _approval(commitment: str) -> StepUpApproval:
    return StepUpApproval(
        approval_id="a-1",
        request_commitment=commitment,
        allow_resources=["repo://deploy/prod.yaml"],
        allow_write=True,
        extra_budget=5,
    )


def test_signed_approval_applies_and_mutates():
    key = generate_keypair()
    req = _request()
    signed = sign_step_up_approval(_approval(req.commitment()), key=key)
    authority = AuthorityContext(authority_id="t", authority_version=1, lease_remaining_calls=2)

    patch = apply_step_up(authority, signed, request_commitment=req.commitment())
    assert "repo://deploy/prod.yaml" in authority.resource_scope
    assert "repo://deploy/prod.yaml" in authority.approval_refs
    assert authority.authority_version == 2
    assert authority.lease_remaining_calls == 7
    assert patch["approval_refs"] == authority.approval_refs


def test_unsigned_approval_refused_by_default():
    authority = AuthorityContext(authority_id="t")
    with pytest.raises(ValueError, match="requires a SignedStepUpApproval"):
        apply_step_up(authority, _approval("sha256:abc"))
    # Nothing was mutated.
    assert authority.resource_scope == []
    assert authority.authority_version == 1


def test_unsigned_allowed_via_explicit_escape_hatch(monkeypatch):
    # The escape hatch is now development-only. Unset, or set to production, the
    # same call raises: an approval grants authority the floor already refused,
    # so an unsigned one is a grant nobody made.
    monkeypatch.setenv("CLAYSEAL_ENV", "development")
    authority = AuthorityContext(authority_id="t", authority_version=1)
    apply_step_up(authority, _approval("sha256:abc"), allow_unsigned=True)
    assert "repo://deploy/prod.yaml" in authority.resource_scope


def test_unsigned_escape_hatch_is_refused_by_default(monkeypatch):
    monkeypatch.delenv("CLAYSEAL_ENV", raising=False)
    monkeypatch.delenv("AGENT_RECEIPTS_ENV", raising=False)
    authority = AuthorityContext(authority_id="t", authority_version=1)
    with pytest.raises(ValueError, match="unsigned step-up approvals are refused"):
        apply_step_up(authority, _approval("sha256:abc"), allow_unsigned=True)
    assert authority.resource_scope == []


def test_signed_approval_bound_to_wrong_request_rejected():
    key = generate_keypair()
    req = _request()
    signed = sign_step_up_approval(_approval(req.commitment()), key=key)
    authority = AuthorityContext(authority_id="t")
    with pytest.raises(ValueError, match="request_commitment mismatch"):
        apply_step_up(authority, signed, request_commitment="sha256:different")
    assert authority.resource_scope == []


def test_tampered_signed_approval_rejected():
    key = generate_keypair()
    req = _request()
    signed = sign_step_up_approval(_approval(req.commitment()), key=key)
    # Widen the approved scope after signing.
    forged = signed.approval.__class__(
        approval_id=signed.approval.approval_id,
        request_commitment=signed.approval.request_commitment,
        allow_resources=[*signed.approval.allow_resources, "repo://secrets/root.key"],
        allow_write=True,
    )
    tampered = signed.__class__(approval=forged, signature=signed.signature)
    ok, reason = verify_step_up_approval(tampered, request_commitment=req.commitment())
    assert not ok and "signature invalid" in reason
