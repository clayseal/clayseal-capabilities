"""Security regression tests for clayseal.core.production."""

from __future__ import annotations

import pytest

from clayseal.core import production as prod


def test_non_production_has_no_violations(monkeypatch):
    monkeypatch.delenv("CLAYSEAL_ENV", raising=False)
    monkeypatch.delenv("AGENT_RECEIPTS_ENV", raising=False)
    assert prod.production_violations(layer="all") == []


def test_production_requires_admin_key_and_allowlist(monkeypatch):
    monkeypatch.setenv("CLAYSEAL_ENV", "production")
    monkeypatch.delenv("CLAYSEAL_ADMIN_API_KEY", raising=False)
    monkeypatch.delenv("CLAYSEAL_HTTP_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("AGENT_RECEIPTS_TRUSTED_SIGNER_PUBLIC_KEYS", raising=False)
    monkeypatch.setenv("AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES", "1")
    violations = prod.production_violations(layer="all")
    assert any("CLAYSEAL_ADMIN_API_KEY" in item for item in violations)
    assert any("CLAYSEAL_HTTP_ALLOWED_HOSTS" in item for item in violations)
    assert any("TRUSTED_SIGNER" in item for item in violations)


def test_production_refuses_dev_attestation(monkeypatch):
    monkeypatch.setenv("CLAYSEAL_ENV", "production")
    with pytest.raises(RuntimeError, match="dev_attestation"):
        prod.refuse_dev_attestation_client(dev_attestation_enabled=True)


def test_production_requires_bundle_signatures_explicit(monkeypatch):
    monkeypatch.setenv("CLAYSEAL_ENV", "production")
    monkeypatch.delenv("AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES", raising=False)
    monkeypatch.setenv("CLAYSEAL_ADMIN_API_KEY", "admin-secret")
    monkeypatch.setenv("CLAYSEAL_HTTP_ALLOWED_HOSTS", "idp.example.com")
    monkeypatch.setenv("AGENT_RECEIPTS_TRUSTED_SIGNER_PUBLIC_KEYS", "aa" * 32)
    violations = prod.production_violations(layer="receipts")
    assert any("AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES" in item for item in violations)


def test_production_accepts_bundle_signatures_when_enabled(monkeypatch):
    monkeypatch.setenv("CLAYSEAL_ENV", "production")
    monkeypatch.setenv("AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES", "1")
    monkeypatch.setenv("CLAYSEAL_ADMIN_API_KEY", "admin-secret")
    monkeypatch.setenv("CLAYSEAL_HTTP_ALLOWED_HOSTS", "idp.example.com")
    monkeypatch.setenv("AGENT_RECEIPTS_TRUSTED_SIGNER_PUBLIC_KEYS", "aa" * 32)
    violations = [
        item
        for item in prod.production_violations(layer="receipts")
        if "AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES" in item
    ]
    assert violations == []


def test_enforce_production_policy_raises(monkeypatch):
    monkeypatch.setenv("CLAYSEAL_ENV", "production")
    monkeypatch.delenv("CLAYSEAL_ADMIN_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="production deployment refused"):
        prod.enforce_production_policy(layer="identity")
