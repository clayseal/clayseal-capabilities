"""Commit-token replay store wiring."""

from __future__ import annotations

from clayseal.capabilities.commit import issue_commit_token, verify_commit_token
from clayseal.capabilities.used_token_store import (
    InMemoryUsedTokenStore,
    set_default_used_token_store,
)
from clayseal.core.runtime import ActionDescriptor, AuthorityContext, ExecutionContext
from clayseal.core.signing import generate_keypair


def _ctx() -> ExecutionContext:
    return ExecutionContext(
        action=ActionDescriptor(action_name="mcp.tools/call/demo", resource_ref="demo"),
        input={"x": 1},
        authority=AuthorityContext(authority_id="auth-1"),
        query_id="q1",
    )


def test_verify_commit_token_uses_default_store_when_configured():
    store = InMemoryUsedTokenStore()
    set_default_used_token_store(store)
    key = generate_keypair()
    ctx = _ctx()
    signed = issue_commit_token(ctx, key=key, ttl_seconds=60)
    pin = {key.public_key_hex}
    ok, reason = verify_commit_token(signed, ctx=ctx, trusted_minting_keys=pin)
    assert ok, reason
    ok2, reason2 = verify_commit_token(signed, ctx=ctx, trusted_minting_keys=pin)
    assert not ok2
    assert reason2 and "replay" in reason2
