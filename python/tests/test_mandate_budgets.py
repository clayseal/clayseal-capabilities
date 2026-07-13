from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agentauth.capabilities.budget import BudgetType, CapabilityBudget
from agentauth.capabilities.mandate import Mandate
from agentauth.capabilities.mandate_budgets import (
    UnsupportedBudgetType,
    session_budgets_from_mandate,
)

_VALUE_TRACKED = {"issue_payroll_bonus": ("bonus_amount", "usd")}
_CALL_TRACKED = {"restart_service": "calls"}


def _mandate(*budgets: CapabilityBudget) -> Mandate:
    now = datetime.now(timezone.utc)
    return Mandate(
        grant_id="g",
        issuer="security-team",
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
        allowed_actions=["issue_payroll_bonus", "restart_service"],
        budgets=list(budgets),
    )


def _usd(limit=1000):
    return CapabilityBudget("usd", BudgetType.USD_LIMIT, "USD", limit, limit)


def _calls(limit=2):
    return CapabilityBudget("calls", BudgetType.TOOL_CALL_LIMIT, "calls", limit, limit)


def _tokens(limit=1000):
    return CapabilityBudget("tok", BudgetType.TOKEN_LIMIT, "tokens", limit, limit)


def test_mixed_mandate_routes_each_kind_to_its_enforcer():
    mb = session_budgets_from_mandate(
        _mandate(_usd(1000), _calls(2)),
        value_tracked=_VALUE_TRACKED,
        call_tracked=_CALL_TRACKED,
    )
    assert mb.value is not None and mb.value.config.ceilings == {"usd": "1000.00"}
    assert mb.calls is not None and mb.calls.config.ceilings == {"calls": 2}

    # And each enforcer actually gates its own dimension.
    r = mb.value.reserve("issue_payroll_bonus", {"bonus_amount": 1500})
    assert not r.allowed and r.reason == "value_budget_exceeded"
    mb.calls.reserve("restart_service", {"target": "a"}).commit()
    mb.calls.reserve("restart_service", {"target": "b"}).commit()
    third = mb.calls.reserve("restart_service", {"target": "c"})
    assert not third.allowed and third.reason == "call_budget_exceeded"


def test_only_value_present_leaves_calls_none():
    mb = session_budgets_from_mandate(_mandate(_usd()), value_tracked=_VALUE_TRACKED)
    assert mb.value is not None
    assert mb.calls is None


def test_only_calls_present_leaves_value_none():
    mb = session_budgets_from_mandate(_mandate(_calls()), call_tracked=_CALL_TRACKED)
    assert mb.calls is not None
    assert mb.value is None


def test_unsupported_budget_type_fails_closed():
    with pytest.raises(UnsupportedBudgetType) as exc:
        session_budgets_from_mandate(
            _mandate(_usd(), _tokens()),
            value_tracked=_VALUE_TRACKED,
        )
    assert "token_limit" in str(exc.value)


def test_allow_unsupported_opt_in_ignores_unenforced_kind():
    mb = session_budgets_from_mandate(
        _mandate(_usd(), _tokens()),
        value_tracked=_VALUE_TRACKED,
        allow_unsupported=True,
    )
    assert mb.value is not None
    assert mb.calls is None  # token budget ignored, not turned into a call/usd ceiling


def test_missing_tracked_for_present_budget_raises():
    with pytest.raises(ValueError, match="USD_LIMIT"):
        session_budgets_from_mandate(_mandate(_usd()))  # no value_tracked
    with pytest.raises(ValueError, match="TOOL_CALL_LIMIT"):
        session_budgets_from_mandate(_mandate(_calls()))  # no call_tracked


def test_dict_form_budgets_are_supported():
    """Budgets can arrive as plain dicts (deserialized mandate), not only dataclasses."""
    now = datetime.now(timezone.utc)
    mandate = {
        "grant_id": "g",
        "issued_at": now.isoformat(),
        "budgets": [
            {"budget_id": "calls", "budget_type": "tool_call_limit",
             "unit": "calls", "limit": 1, "remaining": 1},
        ],
    }
    mb = session_budgets_from_mandate(mandate, call_tracked=_CALL_TRACKED)
    assert mb.calls is not None and mb.calls.config.ceilings == {"calls": 1}
