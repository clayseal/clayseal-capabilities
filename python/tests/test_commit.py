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


def test_commit_token_roundtrip():
    key = generate_keypair()
    ctx = _ctx()
    signed = issue_commit_token(ctx, key=key, ttl_seconds=300)
    ok, reason = verify_commit_token(signed, ctx=ctx)
    assert ok, reason


def test_commit_token_single_use_rejects_replay():
    key = generate_keypair()
    ctx = _ctx()
    signed = issue_commit_token(ctx, key=key, ttl_seconds=300)
    store = InMemoryUsedTokenStore()

    ok1, _ = verify_commit_token(signed, ctx=ctx, used_token_store=store)
    assert ok1
    # Second presentation of the same token is a replay.
    ok2, reason = verify_commit_token(signed, ctx=ctx, used_token_store=store)
    assert not ok2 and reason == "commit token already used (replay)"


def test_commit_token_invalid_does_not_burn_slot():
    key = generate_keypair()
    ctx = _ctx()
    signed = issue_commit_token(ctx, key=key, ttl_seconds=300)
    store = InMemoryUsedTokenStore()

    # A mismatched ctx fails BEFORE the store is consulted, so the same token_id
    # is still usable once the real (matching) call arrives.
    other_ctx = _ctx({"employee_id": "emp_001", "bonus_amount": 999})
    bad, _ = verify_commit_token(signed, ctx=other_ctx, used_token_store=store)
    assert not bad
    ok, _ = verify_commit_token(signed, ctx=ctx, used_token_store=store)
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
