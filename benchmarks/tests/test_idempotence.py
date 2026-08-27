"""Idempotence: the same authorized action twice.

The load-bearing tests are the ones that stop this being another axis renamed.
The replay arm alone is satisfied by refusing every repeat, so the legitimate
arm sits next to it; and containment must be flat at ONE duplicate, because a
mechanism that only fires at three is burst detection wearing a new name.
"""
from __future__ import annotations

import pytest

pytest.importorskip("benchmarks.idempotence")
from benchmarks.idempotence import (  # noqa: E402
    _velocity_on_duplicates, evaluate,
)


def _available(corpus="tau2"):
    from benchmarks.datasets.base import get_loader

    try:
        get_loader(corpus).load(limit=1)
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"{corpus} unavailable: {exc}")


def test_every_arm_clears_the_ladder_below():
    """Without this the benchmark measures scope, not idempotence.

    The duplicate reuses the tool, resource, verb, target and argument shape of
    a call the session already made legitimately, so every rung below has to
    allow it.
    """
    _available()
    r = evaluate("tau2", limit=120)
    assert r.blocked_below == 0, (
        f"{r.blocked_below} arms were blocked below the commit rung; "
        f"this is re-measuring scope"
    )
    assert r.cleared_below > 0


def test_a_replayed_token_is_refused():
    _available()
    assert evaluate("tau2", limit=120).containment == 1.0


def test_a_legitimate_repeat_under_a_fresh_token_is_allowed():
    """tau2 telecom really does call the same tool repeatedly. A mechanism that
    refuses all repeats scores 100% on the replay arm and is useless."""
    _available()
    assert evaluate("tau2", limit=120).false_block == 0.0


def test_containment_is_flat_at_one_duplicate():
    """The distinguishing test. Burst detection needs volume; this must not.

    If containment only appeared at three duplicates, the axis would be volume
    under another name and belongs in burst.py instead.
    """
    _available()
    r = evaluate("tau2", limit=120)
    rates = [r.sweep[n][0] / r.sweep[n][1] for n in (1, 2, 3)]
    assert rates[0] == 1.0
    assert rates == sorted(rates, reverse=True) or len(set(rates)) == 1


def test_velocity_contains_none_of_it():
    """The axis is distinct, asserted rather than argued. One duplicate is not a
    burst and the rate limit correctly says nothing about it."""
    _available()
    for n in (1, 2, 3):
        refused, total = _velocity_on_duplicates("tau2", 120, n)
        assert total > 0
        assert refused == 0, f"velocity caught {refused}/{total} at {n} duplicates"


def test_the_in_memory_store_does_not_survive_a_second_instance():
    """The cost of defaulting through the seam rather than configuring it.

    InMemoryUsedTokenStore is process-local and says so. This is a property of
    the DEV default rather than a hole: verify_commit_token refuses outright when
    is_production() and no store is configured, and RedisUsedTokenStore and
    DynamoDBUsedTokenStore both ship. The arm exists because the in-memory store
    is what a benchmark reaches for by reflex.
    """
    _available()
    r = evaluate("tau2", limit=120)
    assert r.multi_instance_total > 0
    assert r.multi_instance_refused == 0


def test_verification_refuses_by_default_without_a_replay_store(monkeypatch):
    """The half the second-instance arm does not measure.

    A missing store is a configuration error, not a silent loss of replay
    defence, and that is what makes the 0 of 400 above a dev-default number
    rather than a vulnerability.

    This used to read the SOURCE of `verify_commit_token` for the string
    "is_production()", which passed while the guard itself was inert: it only
    applied in a deployment that had set CLAYSEAL_ENV. Asserting on behaviour
    with the variable unset is the check that would have failed then.
    """
    from clayseal.core.runtime import (
        ActionDescriptor,
        AuthorityContext,
        ExecutionContext,
    )
    from clayseal.core.signing import generate_keypair

    from clayseal.capabilities.commit import issue_commit_token, verify_commit_token

    monkeypatch.delenv("CLAYSEAL_ENV", raising=False)
    monkeypatch.delenv("AGENT_RECEIPTS_ENV", raising=False)

    key = generate_keypair()
    ctx = ExecutionContext(
        action=ActionDescriptor(action_name="t/call/pay", resource_ref="acct:1"),
        input={"amount": 1},
        authority=AuthorityContext(authority_id="a"),
        query_id="q",
    )
    token = issue_commit_token(ctx, key=key, ttl_seconds=60)
    ok, reason = verify_commit_token(
        token, ctx=ctx, trusted_minting_keys={key.public_key_hex}
    )
    assert not ok
    assert "replay store required" in reason
