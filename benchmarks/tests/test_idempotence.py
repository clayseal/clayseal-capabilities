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


def test_the_shipped_store_does_not_survive_a_second_instance():
    """Measured rather than left in a docstring.

    InMemoryUsedTokenStore is process-local and says so. A token consumed on one
    instance is invisible to every other, which is the session-scoped ledger
    problem for the third time after principal_ledger and velocity. Behind a load
    balancer the default store contains nothing.
    """
    _available()
    r = evaluate("tau2", limit=120)
    assert r.multi_instance_total > 0
    assert r.multi_instance_refused == 0
