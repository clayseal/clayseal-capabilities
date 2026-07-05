"""Shared pytest fixtures for agent-receipts."""

from __future__ import annotations

import pytest


@pytest.fixture
def allow_stub_proofs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enable stub inference/composed proofs for prove-mode integration tests."""
    monkeypatch.setenv("AGENT_RECEIPTS_ALLOW_STUB", "1")
    monkeypatch.setenv("AGENT_RECEIPTS_ALLOW_UNSIGNED_CERTIFICATE", "1")
    monkeypatch.setenv("AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES", "0")


@pytest.fixture
def trusted_signer(monkeypatch: pytest.MonkeyPatch):
    """Pin a generated Ed25519 key as a trusted envelope signer."""
    from agentauth.core.signing import generate_keypair

    key = generate_keypair()
    monkeypatch.setenv("AGENT_RECEIPTS_TRUSTED_SIGNER_PUBLIC_KEYS", key.public_key_hex)
    return key
