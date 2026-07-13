from __future__ import annotations

from datetime import datetime, timedelta, timezone

from agentauth.capabilities.budget import BudgetType, CapabilityBudget
from agentauth.capabilities.call_budget import (
    CallBudgetConfig,
    SessionCallBudget,
    session_call_budget_from_mandate,
)
from agentauth.capabilities.mandate import Mandate

_TRACKED = {
    "restart_service": "calls",
    "legacy_restart": "calls",  # a second tool debiting the same grant
}


def _mandate(*budgets: CapabilityBudget) -> Mandate:
    now = datetime.now(timezone.utc)
    return Mandate(
        grant_id="g-calls",
        issuer="security-team",
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
        allowed_actions=["restart_service", "legacy_restart"],
        budgets=list(budgets),
    )


def _call_limit(limit: int, remaining: int | None = None) -> CapabilityBudget:
    return CapabilityBudget(
        budget_id="calls",
        budget_type=BudgetType.TOOL_CALL_LIMIT,
        unit="calls",
        limit=limit,
        remaining=limit if remaining is None else remaining,
    )


def test_untracked_tool_is_never_gated():
    b = SessionCallBudget(config=CallBudgetConfig(tracked=_TRACKED, ceilings={"calls": 1}))
    r = b.reserve("some_other_tool", {"target": "x"})
    assert r.allowed and r.reason == "ok_untracked"


def test_no_ceiling_allows_any_count():
    b = SessionCallBudget(config=CallBudgetConfig(tracked=_TRACKED, ceilings={}))
    for i in range(5):
        r = b.reserve("restart_service", {"target": f"svc-{i}"})
        assert r.allowed
        r.commit()


def test_blocks_unauthorized_number_of_valid_calls():
    """The headline case: each call is individually valid, but the grant only
    authorized three, so the fourth must be refused."""
    b = session_call_budget_from_mandate(_mandate(_call_limit(3)), tracked=_TRACKED)
    for i in range(3):
        r = b.reserve("restart_service", {"target": f"svc-{i}"})
        assert r.allowed
        r.commit()
    fourth = b.reserve("restart_service", {"target": "svc-3"})
    assert not fourth.allowed
    assert fourth.reason == "call_budget_exceeded"
    assert b.spent["calls"] == 3
    assert b.remaining("calls") == 0


def test_ceiling_is_tool_agnostic():
    """Switching tools cannot evade the grant: both debit the same budget_id."""
    b = session_call_budget_from_mandate(_mandate(_call_limit(2)), tracked=_TRACKED)
    b.reserve("restart_service", {"target": "a"}).commit()
    b.reserve("legacy_restart", {"target": "b"}).commit()
    third = b.reserve("legacy_restart", {"target": "c"})
    assert not third.allowed and third.reason == "call_budget_exceeded"


def test_uses_remaining_when_lower_than_limit():
    b = session_call_budget_from_mandate(_mandate(_call_limit(5, remaining=1)), tracked=_TRACKED)
    assert b.reserve("restart_service", {"target": "a"}).allowed
    second = b.reserve("restart_service", {"target": "b"})
    assert not second.allowed and second.reason == "call_budget_exceeded"


def test_release_returns_the_slot():
    b = session_call_budget_from_mandate(_mandate(_call_limit(1)), tracked=_TRACKED)
    first = b.reserve("restart_service", {"target": "a"})
    assert first.allowed
    first.release()  # call failed / was rolled back
    second = b.reserve("restart_service", {"target": "b"})
    assert second.allowed  # the slot came back
    second.commit()
    assert b.spent["calls"] == 1


def test_reserved_but_uncommitted_still_counts_against_ceiling():
    """Two concurrent reservations cannot both pass a 1-call ceiling."""
    b = session_call_budget_from_mandate(_mandate(_call_limit(1)), tracked=_TRACKED)
    first = b.reserve("restart_service", {"target": "a"})
    assert first.allowed  # reserved, not yet committed
    second = b.reserve("restart_service", {"target": "b"})
    assert not second.allowed and second.reason == "call_budget_exceeded"


def test_supersession_same_key_does_not_consume_a_new_slot():
    cfg = CallBudgetConfig(
        tracked=_TRACKED, ceilings={"calls": 1},
        supersession_eligible=frozenset({"restart_service"}),
    )
    b = SessionCallBudget(config=cfg)
    first = b.reserve("restart_service", {"target": "a", "_idempotency_key": "k1"})
    assert first.allowed
    first.commit()
    # Same idempotency key = same logical call; must not count as a second slot.
    again = b.reserve("restart_service", {"target": "a", "_idempotency_key": "k1"})
    assert again.allowed
    again.commit()
    assert b.spent["calls"] == 1


def test_tightened_mode_disables_tracked_calls():
    b = session_call_budget_from_mandate(_mandate(_call_limit(5)), tracked=_TRACKED)
    b.enter_tightened_mode()
    r = b.reserve("restart_service", {"target": "a"})
    assert not r.allowed and r.reason == "call_budget_disabled_tightened"
    b.exit_tightened_mode()
    assert b.reserve("restart_service", {"target": "a"}).allowed


def test_would_allow_is_non_mutating():
    b = session_call_budget_from_mandate(_mandate(_call_limit(1)), tracked=_TRACKED)
    ok, reason = b.would_allow("restart_service", {"target": "a"})
    assert ok and reason == "ok"
    # preview did not consume the slot
    assert b.reserve("restart_service", {"target": "a"}).allowed


def test_from_mandate_ignores_non_tool_call_budgets():
    """A USD budget in the same mandate must not create a phantom call ceiling."""
    mandate = _mandate(
        CapabilityBudget(
            budget_id="usd", budget_type=BudgetType.USD_LIMIT, unit="USD",
            limit=1000, remaining=1000,
        ),
        _call_limit(2),
    )
    b = session_call_budget_from_mandate(mandate, tracked=_TRACKED)
    assert b.config.ceilings == {"calls": 2}
    assert "usd" not in b.config.ceilings
