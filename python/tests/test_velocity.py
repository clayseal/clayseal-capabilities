"""Velocity limits: the signal that survives an action having no target.

Built because of a measurement rather than an intuition. Across six corpora, 641
of 833 missed attacks carried no target at all with tool, resource and action
all granted, so every target-binding rung had nothing to check. See
benchmarks/results/why_we_fail.md.

The tests that matter here are the ones about the *shape* of the limit rather
than its arithmetic. A global constant was measured and rejected (54.6% false
blocks on tau2), so the properties worth pinning are that a limit is per task,
that it is opt-in, and that it never fires on the first occurrence.
"""
from __future__ import annotations

import pytest

from agentauth.capabilities.velocity import (
    EFFECT_VERBS,
    SessionVelocity,
    VelocityConfig,
    velocity_from_mandate,
)


def _limiter(max_actions: int, window: float = 3600.0) -> SessionVelocity:
    return SessionVelocity(config=VelocityConfig(
        limits={verb: (max_actions, window) for verb in EFFECT_VERBS}))


def _run(limiter: SessionVelocity, n: int, verb: str = "send", now: float = 0.0) -> int:
    """Attempt n actions; return how many were allowed."""
    allowed = 0
    for _ in range(n):
        if limiter.check("send_email", verb, now=now).allowed:
            limiter.record("send_email", verb, now=now)
            allowed += 1
    return allowed


# --------------------------------------------------------------------------- #
# The property the mechanism exists for
# --------------------------------------------------------------------------- #
def test_a_burst_is_bounded():
    assert _run(_limiter(5), 50) == 5


def test_the_first_action_is_never_blocked():
    """A velocity limit bounds the blast radius of a compromise already under
    way. It cannot decide intent and must not pretend to, so a limit of one
    still admits the first action."""
    assert _limiter(1).check("send_email", "send", now=0.0).allowed


def test_reads_are_not_rate_limited_by_default():
    """A read burst is bulk collection, which the value budget covers. Gating
    reads here would block ordinary work for no containment gain."""
    limiter = _limiter(2)
    assert _run(limiter, 20, verb="read") == 20


def test_unlimited_is_the_default():
    """Adding this module must not change any existing result."""
    limiter = SessionVelocity()
    assert _run(limiter, 100) == 100


# --------------------------------------------------------------------------- #
# Windows
# --------------------------------------------------------------------------- #
def test_capacity_returns_as_the_window_slides():
    limiter = _limiter(3, window=60.0)
    assert _run(limiter, 10, now=0.0) == 3
    assert _run(limiter, 10, now=61.0) == 3


def test_the_window_slides_rather_than_resetting():
    """A counter reset on a fixed schedule lets an attacker align a burst to the
    boundary and take double the rate. A sliding window has no boundary to
    align to."""
    limiter = _limiter(3, window=60.0)
    _run(limiter, 3, now=0.0)
    # Just inside the window: still spent.
    assert not limiter.check("send_email", "send", now=59.0).allowed
    # One action has aged out, so exactly one slot returns.
    assert _run(limiter, 5, now=61.0) == 3


# --------------------------------------------------------------------------- #
# Mandate wiring
# --------------------------------------------------------------------------- #
def test_limits_come_from_the_mandate():
    limiter = velocity_from_mandate(
        {"velocity": {"send": {"max": 2, "window_seconds": 300}}})
    assert _run(limiter, 10) == 2


def test_a_mandate_without_velocity_is_unlimited():
    assert _run(velocity_from_mandate({}), 50) == 50
    assert _run(velocity_from_mandate({"velocity": {}}), 50) == 50


@pytest.mark.parametrize("bad", [
    {"velocity": {"send": "not-a-dict"}},
    {"velocity": {"send": {"window_seconds": 60}}},      # no max
    {"velocity": {"send": {"max": "many"}}},
])
def test_malformed_velocity_config_is_ignored_not_fatal(bad):
    """A policy parse error must not take the enforcement path down, because
    down is open."""
    assert _run(velocity_from_mandate(bad), 10) == 10


def test_classes_are_independent():
    """Exhausting sends must not block writes: they are different budgets."""
    limiter = _limiter(2)
    assert _run(limiter, 5, verb="send") == 2
    assert _run(limiter, 5, verb="write") == 2


def test_observed_counts_only_the_window():
    limiter = _limiter(10, window=60.0)
    _run(limiter, 4, now=0.0)
    assert limiter.observed("send", 60.0, now=30.0) == 4
    assert limiter.observed("send", 60.0, now=120.0) == 0
