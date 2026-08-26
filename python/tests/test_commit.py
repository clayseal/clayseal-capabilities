import threading
from datetime import datetime, timedelta, timezone

from agentauth.core.runtime import ActionDescriptor, AuthorityContext, ExecutionContext
from agentauth.core.signing import generate_keypair
from agentauth.capabilities.commit import (
    InMemoryUsedTokenStore,
    issue_commit_token,
    verify_commit_token,
)


def _ctx(args=None):
    return ExecutionContext(
        action=ActionDescriptor(
            action_name="mcp.tools/call/issue_payroll_bonus",
            resource_ref="rippling-hr:issue_payroll_bonus",
        ),
        input=args if args is not None else {"employee_id": "emp_001", "bonus_amount": 100},
        authority=AuthorityContext(authority_id="rippling-action-agent", tenant_id="ten_demo"),
        query_id="q-demo",
    )


def _verify(signed, *, ctx, key, store=None, **kw):
    """Verify the way a deployment has to: minter pinned, replay store present.

    Both arguments used to be optional in anything but a named production
    environment, so most of this file called `verify_commit_token(signed,
    ctx=ctx)` and passed. That call now fails closed, which is the point, so the
    tests state the whole contract instead of relying on a permissive default.
    """
    return verify_commit_token(
        signed,
        ctx=ctx,
        trusted_minting_keys={key.public_key_hex},
        used_token_store=store if store is not None else InMemoryUsedTokenStore(),
        **kw,
    )


def test_commit_token_roundtrip():
    key = generate_keypair()
    ctx = _ctx()
    signed = issue_commit_token(ctx, key=key, ttl_seconds=300)
    ok, reason = _verify(signed, ctx=ctx, key=key)
    assert ok, reason


def test_commit_token_single_use_rejects_replay():
    key = generate_keypair()
    ctx = _ctx()
    signed = issue_commit_token(ctx, key=key, ttl_seconds=300)
    store = InMemoryUsedTokenStore()

    ok1, _ = _verify(signed, ctx=ctx, key=key, store=store)
    assert ok1
    # Second presentation of the same token is a replay.
    ok2, reason = _verify(signed, ctx=ctx, key=key, store=store)
    assert not ok2 and reason == "commit token already used (replay)"


def test_commit_token_invalid_does_not_burn_slot():
    key = generate_keypair()
    ctx = _ctx()
    signed = issue_commit_token(ctx, key=key, ttl_seconds=300)
    store = InMemoryUsedTokenStore()

    # A mismatched ctx fails BEFORE the store is consulted, so the same token_id
    # is still usable once the real (matching) call arrives.
    other_ctx = _ctx({"employee_id": "emp_001", "bonus_amount": 999})
    bad, _ = _verify(signed, ctx=other_ctx, key=key, store=store)
    assert not bad
    ok, _ = _verify(signed, ctx=ctx, key=key, store=store)
    assert ok


def test_used_token_store_evicts_after_expiry():
    store = InMemoryUsedTokenStore()
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    future = datetime.now(timezone.utc) + timedelta(seconds=60)
    # An already-expired entry is evicted, so the id can be marked used again.
    assert store.mark_used("tok", past) is True
    assert store.mark_used("tok", future) is True
    assert store.mark_used("tok", future) is False


def test_used_token_store_is_thread_safe_single_winner():
    store = InMemoryUsedTokenStore()
    expires = datetime.now(timezone.utc) + timedelta(seconds=60)
    results: list[bool] = []
    lock = threading.Lock()
    barrier = threading.Barrier(16)

    def worker():
        barrier.wait()
        won = store.mark_used("same-token", expires)
        with lock:
            results.append(won)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Exactly one caller may consume a single-use token, no matter the race.
    assert results.count(True) == 1


def test_commit_token_rejects_untrusted_minting_key():
    minting_key = generate_keypair()
    attacker_key = generate_keypair()
    ctx = _ctx()
    forged = issue_commit_token(ctx, key=attacker_key, ttl_seconds=300)

    ok, reason = verify_commit_token(
        forged, ctx=ctx, trusted_minting_keys={minting_key.public_key_hex}
    )
    assert not ok and reason == "commit token signer is not a trusted minting key"


def test_commit_token_accepts_pinned_minting_key_by_public_key_and_key_id():
    key = generate_keypair()
    ctx = _ctx()
    signed = issue_commit_token(ctx, key=key, ttl_seconds=300)

    ok, reason = verify_commit_token(
        signed, ctx=ctx, trusted_minting_keys={key.public_key_hex},
        used_token_store=InMemoryUsedTokenStore(),
    )
    assert ok, reason
    signed2 = issue_commit_token(ctx, key=key, ttl_seconds=300)
    ok2, reason2 = verify_commit_token(
        signed2, ctx=ctx, trusted_minting_keys={key.key_id},
        used_token_store=InMemoryUsedTokenStore(),
    )
    assert ok2, reason2


def test_commit_token_trusted_keys_from_env(monkeypatch):
    key = generate_keypair()
    ctx = _ctx()
    signed = issue_commit_token(ctx, key=key, ttl_seconds=300)
    monkeypatch.setenv(
        "AGENTAUTH_COMMIT_TOKEN_TRUSTED_KEYS", f"ed25519:{key.public_key_hex}"
    )
    store = InMemoryUsedTokenStore()
    ok, reason = verify_commit_token(signed, ctx=ctx, used_token_store=store)
    assert ok, reason

    attacker = generate_keypair()
    forged = issue_commit_token(ctx, key=attacker, ttl_seconds=300)
    ok2, reason2 = verify_commit_token(forged, ctx=ctx, used_token_store=store)
    assert not ok2 and reason2 == "commit token signer is not a trusted minting key"


def test_commit_token_requires_minting_key_pin_by_default(monkeypatch):
    """An UNSET environment is the fail-closed one, which is the whole change.

    This test used to set AGENTAUTH_ENV=production, because without it the same
    call succeeded. A deployment that never set the variable therefore accepted a
    token signed by any key at all, and nothing in the process said so.
    """
    monkeypatch.delenv("AGENTAUTH_ENV", raising=False)
    monkeypatch.delenv("AGENT_RECEIPTS_ENV", raising=False)
    monkeypatch.delenv("AGENTAUTH_COMMIT_TOKEN_TRUSTED_KEYS", raising=False)
    key = generate_keypair()
    ctx = _ctx()
    signed = issue_commit_token(ctx, key=key, ttl_seconds=300)
    ok, reason = verify_commit_token(signed, ctx=ctx)
    assert not ok
    assert reason and "trusted minting keys required" in reason


def test_commit_token_pin_can_be_relaxed_for_development(monkeypatch, recwarn):
    """The relaxed path still exists, has to be named, and announces itself."""
    from agentauth.core.production import reset_relaxed_warning

    reset_relaxed_warning()
    monkeypatch.setenv("AGENTAUTH_ENV", "development")
    monkeypatch.delenv("AGENTAUTH_COMMIT_TOKEN_TRUSTED_KEYS", raising=False)
    key = generate_keypair()
    ctx = _ctx()
    signed = issue_commit_token(ctx, key=key, ttl_seconds=300)
    ok, reason = verify_commit_token(signed, ctx=ctx)
    assert ok, reason
    assert any("enforcement guards relaxed" in str(w.message) for w in recwarn)
