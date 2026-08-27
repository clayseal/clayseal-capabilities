"""Replay defense is where single-use actually lives.

`commit_totality.md` proves the verifier binds every field. All of it is
conditional on the store: if `mark_used` says "new" twice, a one-shot
authorization becomes a standing grant until expiry, and nothing above the token
re-checks it. The store is also the only component that is concurrent,
distributed and network-dependent, which is why it gets its own attacks.
"""
from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest

from clayseal.capabilities.commit import (
    InMemoryUsedTokenStore,
    verify_commit_token,
)
from benchmarks.stress_replay import (
    FlakyStore,
    attack_hostile_input,
    attack_race,
    attack_scaling,
)
from benchmarks.stress_commit import _pair

FUTURE = datetime.now(timezone.utc) + timedelta(hours=1)


def test_exactly_one_of_many_concurrent_presentations_wins():
    """The double-spend. Two instances behind a load balancer calling
    `verify_commit_token` at the same instant is not an edge case."""
    result = attack_race(threads=64)
    assert result["winners"] == 1, result


def test_a_replay_store_outage_denies_rather_than_raising():
    """Fail-closed, with a verdict.

    `RedisUsedTokenStore.mark_used` is a bare `client.set(...)`, so a partition
    used to send `ConnectionError` straight out of the verifier. Technically
    fail-closed, but it forces every integrator to implement the deny, and the
    first one to wrap this in a broad `except` turns a partition into whatever
    their fallback does.
    """
    signed, ctx, trusted = _pair()
    for exc in (ConnectionError("redis down"), TimeoutError("dynamo timeout")):
        ok, reason = verify_commit_token(
            signed, ctx=ctx, trusted_minting_keys=trusted,
            used_token_store=FlakyStore(exc))
        assert not ok
        assert "replay store unavailable" in (reason or "")


def test_a_store_outage_is_never_an_allow():
    """The property that matters more than the shape of the failure."""
    signed, ctx, trusted = _pair()
    for exc in (ConnectionError(), TimeoutError(), RuntimeError(), OSError()):
        ok, _ = verify_commit_token(
            signed, ctx=ctx, trusted_minting_keys=trusted,
            used_token_store=FlakyStore(exc))
        assert not ok, f"{type(exc).__name__} produced an ALLOW"


def test_marking_tokens_is_not_quadratic():
    """`_evict` used to rebuild a list over every entry on every call: 32.5us
    per mark at token 2,000 and 402.8us at token 20,000, on traffic that should
    be flat. An attacker inflates the live set on purpose by issuing tokens."""
    result = attack_scaling(tokens=20000)
    assert result["violation"] is None, result
    assert result["ratio"] < 5, result


def test_hostile_token_ids_do_not_crash_or_collide():
    result = attack_hostile_input()
    assert result["violation"] is None, result


# --------------------------------------------------------------------------- #
# Eviction correctness, the part the heap could get wrong.
# --------------------------------------------------------------------------- #
def test_an_expired_token_id_can_be_marked_again():
    store = InMemoryUsedTokenStore()
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert store.mark_used("tok", past) is True
    assert store.mark_used("tok", FUTURE) is True, (
        "an expired entry must not block a fresh one")


def test_a_stale_heap_entry_does_not_evict_a_live_record():
    """The staleness guard.

    Re-marking a token after its first entry expired leaves the old heap entry
    behind. Popping it must not delete the live record, or the token becomes
    replayable exactly once per eviction pass.
    """
    store = InMemoryUsedTokenStore()
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    store.mark_used("tok", past)          # entry 1, already expired
    store.mark_used("tok", FUTURE)        # entry 2, live
    for i in range(50):                   # force eviction passes
        store.mark_used(f"filler-{i}", FUTURE)
    assert store.mark_used("tok", FUTURE) is False, (
        "the live record was evicted by its own stale heap entry")


def test_an_unexpired_token_is_still_refused_on_second_presentation():
    store = InMemoryUsedTokenStore()
    assert store.mark_used("tok", FUTURE) is True
    assert store.mark_used("tok", FUTURE) is False


def test_distinct_tokens_are_independent():
    store = InMemoryUsedTokenStore()
    assert store.mark_used("a", FUTURE) is True
    assert store.mark_used("b", FUTURE) is True
    assert store.mark_used("a", FUTURE) is False
    assert store.mark_used("b", FUTURE) is False


def test_the_ledger_does_not_grow_without_bound():
    """Expired entries must actually leave, or the store is a memory leak with
    a lock around it."""
    store = InMemoryUsedTokenStore()
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    for i in range(5000):
        store.mark_used(f"tok-{i}", past)
    store.mark_used("trigger", FUTURE)
    assert len(store._seen) < 100, len(store._seen)


def test_concurrent_marks_of_distinct_tokens_all_succeed():
    """The lock must not be so coarse that it loses marks."""
    store = InMemoryUsedTokenStore()
    results: list[bool] = []
    lock = threading.Lock()

    def worker(i: int) -> None:
        got = store.mark_used(f"tok-{i}", FUTURE)
        with lock:
            results.append(got)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(64)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(results) and len(results) == 64
