"""Security regression tests for clayseal.core.signing and delegation."""

from __future__ import annotations

from uuid import uuid4

import pytest

from clayseal.core.delegation import (
    issue_delegation,
    sign_delegation,
    verify_delegation_chain,
    verify_delegation_envelope,
)
from clayseal.core.mandate import mandate_signer_matches_issuer
from clayseal.core.signing import generate_keypair, load_or_create_key, sign, verify


def test_delegation_requires_signature_by_default():
    token = issue_delegation(
        None,
        delegate_agent_id=uuid4(),
        capabilities=[{"resource": "mcp:tool", "action": "call"}],
    )
    violations = verify_delegation_chain(token)
    assert any("not cryptographically signed" in item for item in violations)


def test_signed_delegation_passes_default_signature_requirement():
    key = generate_keypair()
    token = issue_delegation(
        None,
        delegate_agent_id=uuid4(),
        capabilities=[{"resource": "mcp:tool", "action": "call"}],
    )
    envelope = sign_delegation(token, key)
    from clayseal.core.delegation import delegation_from_envelope

    parsed = delegation_from_envelope(envelope)
    assert verify_delegation_chain(parsed, signed_envelope=envelope) == []


def test_delegation_child_chain_requires_signed_parent_envelope():
    key = generate_keypair()
    root = issue_delegation(
        None,
        delegate_agent_id=uuid4(),
        capabilities=[{"resource": "db", "action": "read"}],
    )
    root_envelope = sign_delegation(root, key)
    child = issue_delegation(
        None,
        parent_envelope=root_envelope,
        delegate_agent_id=uuid4(),
        capabilities=[{"resource": "db", "action": "read"}],
    )
    child_envelope = sign_delegation(child, key, parent_envelope=root_envelope)
    assert verify_delegation_envelope(child_envelope, verify_chain=True) == []


def test_delegation_rejects_tampered_parent_commitment():
    key = generate_keypair()
    root = issue_delegation(
        None,
        delegate_agent_id=uuid4(),
        capabilities=[{"resource": "db", "action": "read"}],
    )
    root_envelope = sign_delegation(root, key)
    child = issue_delegation(
        None,
        parent_envelope=root_envelope,
        delegate_agent_id=uuid4(),
        capabilities=[{"resource": "db", "action": "read"}],
    )
    child_envelope = sign_delegation(child, key, parent_envelope=root_envelope)
    child_envelope["document"]["parent_commitment"] = "deadbeef"
    assert verify_delegation_envelope(child_envelope, verify_chain=True)


def test_sign_verify_roundtrip():
    key = generate_keypair()
    document = {"schema": "test.v1", "value": 42}
    signature = sign(document, key)
    assert verify(document, signature) is True
    document["value"] = 43
    assert verify(document, signature) is False


def test_mandate_signer_rejects_self_referential_issuer_in_production(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAYSEAL_ENV", "production")
    public_key = "aa" * 32
    signature = {"public_key": public_key, "key_id": "issuer-1"}
    assert mandate_signer_matches_issuer(public_key, signature) is False
    assert mandate_signer_matches_issuer("issuer-1", signature) is True


def test_load_or_create_key_refuses_unencrypted_in_production(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAYSEAL_ENV", "production")
    dest = tmp_path / "agent_ed25519.key"
    with pytest.raises(ValueError, match="refusing to create unencrypted"):
        load_or_create_key(dest)
