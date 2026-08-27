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

from clayseal.capabilities.velocity import (
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


# --------------------------------------------------------------------------- #
# Rate classes. Every one of these silently disabled the limit it appeared on.
# --------------------------------------------------------------------------- #
def test_a_per_verb_limit_does_not_leave_the_other_effect_verbs_unlimited():
    """The hole an operator does not expect to have left open.

    A mandate declaring 20 sends per hour has bounded sends and nothing else:
    the other eight effect verbs went through the same tool unlimited. The
    aggregate `effect` class bounds all of them at once.
    """
    v = velocity_from_mandate({"velocity": {"effect": {"max": 2, "window_seconds": 3600}}})
    allowed = sum(
        v.try_acquire("mailer", verb, now=0.0).allowed
        for verb in ("send", "post", "write", "create", "update",
                     "transfer", "delete", "pay", "execute")
    )
    assert allowed == 2


def test_a_per_verb_limit_and_the_aggregate_both_bind():
    v = velocity_from_mandate({"velocity": {
        "effect": {"max": 10, "window_seconds": 3600},
        "send": {"max": 2, "window_seconds": 3600},
    }})
    sends = sum(v.try_acquire("mailer", "send", now=0.0).allowed for _ in range(5))
    assert sends == 2
    # The aggregate still has room, and the two sends counted against it.
    writes = sum(v.try_acquire("editor", "write", now=0.0).allowed for _ in range(20))
    assert writes == 8


def test_the_action_verb_is_normalised_before_lookup():
    """The verb comes from the agent's own tool call. `SEND` used to miss a
    limit declared on `send` entirely: twenty calls passed a cap of two."""
    v = velocity_from_mandate({"velocity": {"send": {"max": 2, "window_seconds": 3600}}})
    assert sum(v.try_acquire("m", "SEND", now=0.0).allowed for _ in range(20)) == 2
    v2 = velocity_from_mandate({"velocity": {"send": {"max": 2, "window_seconds": 3600}}})
    assert sum(v2.try_acquire("m", " send ", now=0.0).allowed for _ in range(20)) == 2


@pytest.mark.parametrize("window", ["-inf", "0", "-1", "nan"])
def test_a_window_that_disables_the_limit_is_rejected_not_stored(window):
    v = velocity_from_mandate({"velocity": {"send": {"max": 1, "window_seconds": window}}})
    assert "send" in v.config.rejected
    assert v.config.limit_for("send") is None


def test_a_max_below_one_is_rejected():
    v = velocity_from_mandate({"velocity": {"send": {"max": 0, "window_seconds": 60}}})
    assert "send" in v.config.rejected


def test_a_boolean_max_is_rejected():
    """bool is an int in Python, so `True` silently became a cap of one."""
    v = velocity_from_mandate({"velocity": {"send": {"max": True, "window_seconds": 60}}})
    assert "send" in v.config.rejected


def test_an_unknown_rate_class_is_reported_rather_than_silently_inert():
    """It used to be parsed, stored, and never applied, so the mandate said one
    thing and the enforcement did another."""
    v = velocity_from_mandate({"velocity": {"outbound_email": {"max": 1}}})
    assert "outbound_email" in v.config.rejected
    assert sum(v.try_acquire("mailer", "send", now=0.0).allowed for _ in range(10)) == 10


def test_a_mandate_may_declare_its_own_classes_through_tool_classes():
    v = velocity_from_mandate({"velocity": {
        "tool_classes": {"mailer": "outbound_email"},
        "outbound_email": {"max": 1, "window_seconds": 60},
    }})
    assert not v.config.rejected
    assert sum(v.try_acquire("mailer", "send", now=0.0).allowed for _ in range(5)) == 1


def test_strict_mode_raises_instead_of_dropping():
    with pytest.raises(ValueError):
        velocity_from_mandate(
            {"velocity": {"send": {"max": 1, "window_seconds": 0}}}, strict=True)


def test_a_refused_action_gives_back_every_class_it_acquired():
    v = velocity_from_mandate({"velocity": {
        "effect": {"max": 3, "window_seconds": 3600},
        "send": {"max": 3, "window_seconds": 3600},
    }})
    assert v.try_acquire("m", "send", now=1.0).allowed
    v.release("m", "send", now=1.0)
    assert v.observed("effect", 3600.0, now=1.0) == 0
    assert v.observed("send", 3600.0, now=1.0) == 0


# --------------------------------------------------------------------------- #
# Principal scope. The structuring lesson, applied here at last.
# --------------------------------------------------------------------------- #
def test_a_session_scoped_cap_is_reset_by_opening_another_session():
    """The defect, pinned so it cannot come back.

    SessionVelocity is per object, so a new session is a new empty window. A
    declared cap of seven effect actions per hour admitted fifty-six when the
    same work was split across eight sessions. The agent needs no capability it
    did not already have: it opens another conversation.
    """
    mandate = {"velocity": {"effect": {"max": 7, "window_seconds": 3600}}}
    total = 0
    for _ in range(8):
        limiter = velocity_from_mandate(mandate)
        total += sum(limiter.try_acquire("m", "send", now=0.0).allowed for _ in range(7))
    assert total == 56, "the session-scoped hole should still be demonstrable"


def test_a_principal_scoped_cap_survives_new_sessions():
    from clayseal.capabilities.velocity import (
        PrincipalVelocity, PrincipalVelocityView)

    mandate = {"velocity": {"effect": {"max": 7, "window_seconds": 3600}}}
    ledger = PrincipalVelocity(config=velocity_from_mandate(mandate).config)
    total = 0
    for _ in range(8):
        view = PrincipalVelocityView(ledger=ledger, principal="mandate:assistant")
        total += sum(view.try_acquire("m", "send", now=0.0).allowed for _ in range(7))
    assert total == 7


def test_one_principal_does_not_consume_another_principals_rate():
    from clayseal.capabilities.velocity import (
        PrincipalVelocity, PrincipalVelocityView)

    mandate = {"velocity": {"effect": {"max": 3, "window_seconds": 3600}}}
    ledger = PrincipalVelocity(config=velocity_from_mandate(mandate).config)
    a = PrincipalVelocityView(ledger=ledger, principal="mandate:a")
    b = PrincipalVelocityView(ledger=ledger, principal="mandate:b")
    assert sum(a.try_acquire("m", "send", now=0.0).allowed for _ in range(5)) == 3
    assert sum(b.try_acquire("m", "send", now=0.0).allowed for _ in range(5)) == 3


def test_the_principal_window_still_slides():
    from clayseal.capabilities.velocity import (
        PrincipalVelocity, PrincipalVelocityView)

    mandate = {"velocity": {"effect": {"max": 2, "window_seconds": 100}}}
    ledger = PrincipalVelocity(config=velocity_from_mandate(mandate).config)
    view = PrincipalVelocityView(ledger=ledger, principal="p")
    assert sum(view.try_acquire("m", "send", now=float(i)).allowed for i in range(5)) == 2
    assert view.try_acquire("m", "send", now=500.0).allowed


def test_a_patient_attacker_below_the_declared_rate_is_not_contained():
    """The honest limit of any rate limit, asserted rather than left implicit.

    Forty sends at ten-minute intervals pass a cap of seven per hour, because
    four per hour is not a burst. A rate limit bounds the rate; it does not bound
    the total, and a patient adversary simply goes slower. The burst benchmark's
    100% means 100% of bursts ABOVE the declared rate, and quoting it without
    this sentence would overstate it.
    """
    from clayseal.capabilities.velocity import (
        PrincipalVelocity, PrincipalVelocityView)

    mandate = {"velocity": {"effect": {"max": 7, "window_seconds": 3600}}}
    ledger = PrincipalVelocity(config=velocity_from_mandate(mandate).config)
    view = PrincipalVelocityView(ledger=ledger, principal="p")
    allowed = sum(view.try_acquire("m", "send", now=float(i * 600)).allowed
                  for i in range(40))
    assert allowed == 40
