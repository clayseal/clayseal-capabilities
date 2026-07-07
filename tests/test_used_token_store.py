from __future__ import annotations

import pytest

from agentauth.capabilities import used_token_store as stores
from agentauth.capabilities.commit import InMemoryUsedTokenStore


@pytest.fixture(autouse=True)
def reset_default_store():
    stores._DEFAULT_STORE = stores._UNSET
    yield
    stores._DEFAULT_STORE = stores._UNSET


def test_default_used_token_store_initializes_to_none(monkeypatch):
    monkeypatch.delenv("AGENTAUTH_COMMIT_TOKEN_STORE", raising=False)
    monkeypatch.delenv("AGENTAUTH_COMMIT_TOKEN_REDIS_URL", raising=False)
    monkeypatch.delenv("AGENTAUTH_COMMIT_TOKEN_DYNAMODB_TABLE", raising=False)

    assert stores.default_used_token_store() is None


def test_default_used_token_store_can_be_set_explicitly():
    store = InMemoryUsedTokenStore()
    stores.set_default_used_token_store(store)

    assert stores.default_used_token_store() is store


def test_unknown_store_config_raises(monkeypatch):
    monkeypatch.setenv("AGENTAUTH_COMMIT_TOKEN_STORE", "bogus")

    with pytest.raises(ValueError, match="unsupported AGENTAUTH_COMMIT_TOKEN_STORE"):
        stores.default_used_token_store()
