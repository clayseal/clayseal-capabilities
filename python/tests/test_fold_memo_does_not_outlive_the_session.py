"""A memo whose keys are secrets must die with the session that read them.

`_reconstructed_from_stream` folds every sensitive token the session has seen on
every decision, though the tokens do not change between decisions. Memoising that
is worth about 4x at 400 tokens, which is the shape where the tail lives.

The first version memoised with an `lru_cache` on the module-level function. That
is faster still — 1.7 ms against 2.5 ms at 400 tokens — and wrong, because the
cache keys ARE the sensitive values. A process-global cache keeps a secret read by
one session resident after that session is gone and shares it with every later
one. Verified before it was changed: the secret was still cached after the tracker
was deleted and garbage collected.

So the memo lives on the tracker. It costs about 1.4x against the global cache and
still runs 4.1x faster than no memo at all:

    tokens      none      global cache      per session
         1     0.685            0.357            0.616
        50     2.045            0.484            0.815
       400    10.387            1.745            2.505

This file holds the property, not the speed. Speed is in
`test_no_catastrophic_backtracking.py`.
"""
from __future__ import annotations

import gc

from clayseal.capabilities import confidentiality
from clayseal.capabilities.confidentiality import FlowTracker, SensitivityPolicy

SECRET = "SUPERSECRET-VALUE-1234567890"


def _session() -> tuple[FlowTracker, SensitivityPolicy]:
    policy = SensitivityPolicy(sensitive=("secrets/**",), argument_sinks=("net:**",))
    tracker = FlowTracker()
    tracker.observe("read_file", "secrets/k", SECRET, policy=policy, path="secrets/k")
    tracker.check(tool="send", verb="send", resource="net:x",
                  args={"body": "an ordinary write"}, policy=policy)
    return tracker, policy


def test_the_fold_functions_carry_no_process_global_cache():
    """The regression this file exists for. An `lru_cache` here would hold
    secrets for the life of the process."""
    for name in ("_fold", "_compact_fold"):
        fn = getattr(confidentiality, name)
        assert not hasattr(fn, "cache_info"), (
            f"{name} has a process-global cache, and its keys are sensitive values")


def test_the_memo_is_populated_during_the_session():
    """Otherwise the test below passes because nothing was ever memoised."""
    tracker, _ = _session()
    assert tracker._fold_memo, "no fold was memoised; the speedup is not happening"


def test_the_memo_dies_with_the_tracker():
    tracker, _ = _session()
    memo = tracker._fold_memo
    assert any(SECRET in key for key in memo), "the secret should be a memo key"
    del tracker
    gc.collect()
    # The memo is reachable only from the tracker, so a NEW session starts empty.
    fresh = FlowTracker()
    assert fresh._fold_memo == {}, "a new session inherited a previous one's folds"


def test_two_sessions_do_not_share_folds():
    """The property a global cache breaks: session B must not be able to observe
    what session A read, by any route including a timing side channel on a
    shared cache."""
    a, _ = _session()
    b = FlowTracker()
    assert a._fold_memo
    assert b._fold_memo == {}
    assert a._fold_memo is not b._fold_memo


def test_the_memo_is_bounded():
    """The keys are attacker-influenced: a payload can introduce a new spelling
    on every call, so an unbounded memo is a leak reachable from a tool
    argument."""
    tracker = FlowTracker()
    cap = confidentiality._FOLD_CACHE
    for i in range(cap + 200):
        tracker._folded(f"token-{i}")
    assert len(tracker._fold_memo) <= cap, len(tracker._fold_memo)


def test_memoised_and_unmemoised_folds_agree():
    """The control. A memo that returned something different from the function it
    memoises would be a correctness bug wearing a performance fix."""
    tracker = FlowTracker()
    for value in (SECRET, "", "MiXeD-Case", "with spaces", "аttacker.com", "x" * 500):
        assert tracker._folded(value) == confidentiality._compact_fold(value)
        assert tracker._folded(value) == confidentiality._compact_fold(value)  # cached path
