"""Tests for distributed commit-token replay stores."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from clayseal.capabilities import used_token_store as stores
from clayseal.capabilities.commit import InMemoryUsedTokenStore
from clayseal.capabilities.used_token_store import load_used_token_store_from_env


def test_in_memory_store_rejects_replay():
    store = InMemoryUsedTokenStore()
    expires = datetime.now(timezone.utc) + timedelta(seconds=60)
    assert store.mark_used("tok-1", expires) is True
    assert store.mark_used("tok-1", expires) is False


def test_load_memory_store_from_env(monkeypatch):
    monkeypatch.setenv("CLAYSEAL_COMMIT_TOKEN_STORE", "memory")
    store = load_used_token_store_from_env()
    assert isinstance(store, InMemoryUsedTokenStore)


@pytest.fixture(autouse=True)
def reset_default_store():
    stores._DEFAULT_STORE = stores._UNSET
    yield
    stores._DEFAULT_STORE = stores._UNSET


def test_default_used_token_store_initializes_to_none(monkeypatch):
    monkeypatch.delenv("CLAYSEAL_COMMIT_TOKEN_STORE", raising=False)
    monkeypatch.delenv("CLAYSEAL_COMMIT_TOKEN_REDIS_URL", raising=False)
    monkeypatch.delenv("CLAYSEAL_COMMIT_TOKEN_DYNAMODB_TABLE", raising=False)

    assert stores.default_used_token_store() is None


def test_default_used_token_store_can_be_set_explicitly():
    store = InMemoryUsedTokenStore()
    stores.set_default_used_token_store(store)

    assert stores.default_used_token_store() is store


def test_unknown_store_config_raises(monkeypatch):
    monkeypatch.setenv("CLAYSEAL_COMMIT_TOKEN_STORE", "bogus")

    with pytest.raises(ValueError, match="unsupported CLAYSEAL_COMMIT_TOKEN_STORE"):
        stores.default_used_token_store()