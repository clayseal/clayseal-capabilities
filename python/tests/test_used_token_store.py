"""Tests for distributed commit-token replay stores."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from agentauth.capabilities.commit import InMemoryUsedTokenStore
from agentauth.capabilities.used_token_store import load_used_token_store_from_env


def test_in_memory_store_rejects_replay():
    store = InMemoryUsedTokenStore()
    expires = datetime.now(timezone.utc) + timedelta(seconds=60)
    assert store.mark_used("tok-1", expires) is True
    assert store.mark_used("tok-1", expires) is False


def test_load_memory_store_from_env(monkeypatch):
    monkeypatch.setenv("AGENTAUTH_COMMIT_TOKEN_STORE", "memory")
    store = load_used_token_store_from_env()
    assert isinstance(store, InMemoryUsedTokenStore)
