"""Tests for agentauth.core.safe_http."""

from __future__ import annotations

import pytest

from agentauth.core.safe_http import SafeHttpError, _NoRedirectHandler, validate_outbound_url


def test_validate_https_public_host_ok(monkeypatch):
    monkeypatch.delenv("AGENTAUTH_ENV", raising=False)
    monkeypatch.delenv("AGENT_RECEIPTS_ENV", raising=False)
    url = validate_outbound_url(
        "https://token.actions.githubusercontent.com/.well-known/jwks",
        allowed_hosts=["token.actions.githubusercontent.com"],
        resolve_dns=False,
    )
    assert url.startswith("https://")


def test_validate_rejects_http_by_default(monkeypatch):
    monkeypatch.delenv("AGENTAUTH_ENV", raising=False)
    with pytest.raises(SafeHttpError, match="https"):
        validate_outbound_url(
            "http://example.com/jwks.json",
            allowed_hosts=["example.com"],
            resolve_dns=False,
        )


def test_validate_rejects_localhost(monkeypatch):
    monkeypatch.delenv("AGENTAUTH_ENV", raising=False)
    with pytest.raises(SafeHttpError, match="blocked"):
        validate_outbound_url(
            "https://localhost/jwks.json",
            allowed_hosts=["localhost"],
            resolve_dns=False,
        )


def test_validate_rejects_private_literal(monkeypatch):
    monkeypatch.delenv("AGENTAUTH_ENV", raising=False)
    with pytest.raises(SafeHttpError, match="globally routable"):
        validate_outbound_url(
            "https://10.0.0.1/jwks.json",
            allowed_hosts=["10.0.0.1"],
            resolve_dns=False,
        )


def test_production_requires_allowlist(monkeypatch):
    monkeypatch.setenv("AGENTAUTH_ENV", "production")
    monkeypatch.delenv("AGENTAUTH_HTTP_ALLOWED_HOSTS", raising=False)
    with pytest.raises(SafeHttpError, match="AGENTAUTH_HTTP_ALLOWED_HOSTS"):
        validate_outbound_url(
            "https://idp.example.com/.well-known/openid-configuration",
            resolve_dns=False,
        )


def test_production_allows_configured_host(monkeypatch):
    monkeypatch.setenv("AGENTAUTH_ENV", "production")
    monkeypatch.setenv("AGENTAUTH_HTTP_ALLOWED_HOSTS", "idp.example.com")
    url = validate_outbound_url(
        "https://idp.example.com/.well-known/openid-configuration",
        resolve_dns=False,
    )
    assert "idp.example.com" in url


def test_urlopen_redirect_handler_fails_closed():
    handler = _NoRedirectHandler()

    with pytest.raises(SafeHttpError, match="redirects"):
        handler.redirect_request(None, None, 302, "Found", {}, "https://example.com/next")
