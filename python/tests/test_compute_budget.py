"""Compute-seconds ledger, and the honesty boundary around data_export_bytes."""
import pytest
from agentauth.core.mandate import Mandate

from agentauth.capabilities.budget import BudgetType, CapabilityBudget
from agentauth.capabilities.compute_budget import (
    SessionComputeBudget,
    session_compute_budget_from_mandate,
)
from agentauth.capabilities.mandate_budgets import (
    SUPPORTED_BUDGET_TYPES,
    UnsupportedBudgetType,
    session_budgets_from_mandate,
)

TRACKED = {"run_code": "b-compute"}


def _mandate(budget_type=BudgetType.COMPUTE_SECONDS, limit=600.0, remaining=None):
    return Mandate(
        grant_id="g1", issuer="did:test", issued_at="2026-01-01T00:00:00Z",
        expires_at="2030-01-01T00:00:00Z", delegate="agent-1",
        budgets=[CapabilityBudget(
            budget_id="b-compute", budget_type=budget_type, unit="seconds",
            limit=limit, remaining=limit if remaining is None else remaining)])


def _budget(ceiling=10.0):
    return session_compute_budget_from_mandate(
        _mandate(limit=ceiling), tracked=TRACKED)


def test_reserve_then_commit_charges_actual_seconds():
    budget = _budget(ceiling=10.0)
    res = budget.reserve("run_code", 5.0)
    assert res.allowed and res.granted_seconds == 5.0
    res.commit(2.5)
    assert budget.spent["b-compute"] == 2.5
    assert budget.remaining("b-compute") == 7.5


def test_commit_without_an_actual_charges_the_reservation():
    budget = _budget(ceiling=10.0)
    budget.reserve("run_code", 4.0).commit()
    assert budget.spent["b-compute"] == 4.0


def test_release_refunds_the_whole_reservation():
    budget = _budget(ceiling=10.0)
    res = budget.reserve("run_code", 6.0)
    res.release()
    assert budget.remaining("b-compute") == 10.0
    assert budget.spent.get("b-compute", 0.0) == 0.0


def test_reservation_is_held_against_a_concurrent_reserve():
    # The reservation must be visible to the next caller before it commits,
    # or two parallel runs each see the full ceiling.
    budget = _budget(ceiling=10.0)
    first = budget.reserve("run_code", 8.0)
    second = budget.reserve("run_code", 8.0)
    assert first.granted_seconds == 8.0
    assert second.granted_seconds == 2.0  # clamped to what is left


def test_grant_is_clamped_not_refused_when_partially_available():
    # The clamp is the point: the run is authorized for exactly the time left,
    # and the caller uses granted_seconds as the sandbox timeout.
    budget = _budget(ceiling=10.0)
    budget.reserve("run_code", 7.0).commit(7.0)
    res = budget.reserve("run_code", 30.0)
    assert res.allowed and res.granted_seconds == 3.0
    assert res.reason == "ok_clamped"


def test_exhausted_budget_refuses():
    budget = _budget(ceiling=5.0)
    budget.reserve("run_code", 5.0).commit(5.0)
    res = budget.reserve("run_code", 1.0)
    assert not res.allowed
    assert res.reason == "compute_budget_exhausted"


def test_overshoot_is_charged_what_it_used():
    budget = _budget(ceiling=10.0)
    res = budget.reserve("run_code", 3.0)
    res.commit(4.5)   # timeout slop
    assert budget.spent["b-compute"] == 4.5


def test_settlement_is_idempotent():
    budget = _budget(ceiling=10.0)
    res = budget.reserve("run_code", 4.0)
    res.commit(4.0)
    res.commit(4.0)
    res.release()
    assert budget.spent["b-compute"] == 4.0


def test_untracked_tool_passes_through():
    budget = _budget()
    res = budget.reserve("some_other_tool", 99.0)
    assert res.allowed and res.reason == "ok_untracked"
    assert res.granted_seconds == 99.0


def test_tightened_mode_refuses():
    budget = _budget()
    budget.enter_tightened_mode()
    assert not budget.reserve("run_code", 1.0).allowed
    budget.exit_tightened_mode()
    assert budget.reserve("run_code", 1.0).allowed


def test_would_allow_does_not_consume():
    budget = _budget(ceiling=10.0)
    assert budget.would_allow("run_code")[0] is True
    assert budget.remaining("b-compute") == 10.0


def test_no_ceiling_means_unmetered_but_still_tracked():
    budget = SessionComputeBudget()
    budget.config.tracked = dict(TRACKED)
    res = budget.reserve("run_code", 3.0)
    assert res.allowed and res.reason == "ok_no_ceiling"
    res.commit(3.0)
    assert budget.spent["b-compute"] == 3.0


def test_negative_estimate_is_rejected():
    with pytest.raises(ValueError):
        _budget().reserve("run_code", -1.0)


def test_to_dict_serializes():
    budget = _budget(ceiling=10.0)
    budget.reserve("run_code", 2.0).commit(2.0)
    payload = budget.to_dict()
    assert payload["spent"]["b-compute"] == 2.0
    assert payload["ceilings"]["b-compute"] == 10.0


# --------------------------------------------------------------------------- #
# Mandate dispatch
# --------------------------------------------------------------------------- #

def test_compute_seconds_is_now_a_supported_budget_type():
    assert BudgetType.COMPUTE_SECONDS in SUPPORTED_BUDGET_TYPES


def test_mandate_with_compute_budget_builds_an_enforcer():
    budgets = session_budgets_from_mandate(_mandate(), compute_tracked=TRACKED)
    assert budgets.compute is not None
    assert budgets.compute.remaining("b-compute") == 600.0


def test_compute_budget_without_tracked_map_is_an_error():
    with pytest.raises(ValueError, match="compute_tracked"):
        session_budgets_from_mandate(_mandate())


def test_remaining_is_respected_over_limit():
    mandate = _mandate(limit=600.0, remaining=100.0)
    budgets = session_budgets_from_mandate(mandate, compute_tracked=TRACKED)
    assert budgets.compute.remaining("b-compute") == 100.0


def test_data_export_bytes_still_fails_closed():
    # iVisor reports which destinations were reached, not how many bytes
    # crossed. Admitting this grant would mean pretending to enforce it.
    mandate = _mandate(budget_type=BudgetType.DATA_EXPORT_BYTES, limit=1024)
    with pytest.raises(UnsupportedBudgetType, match="data_export_bytes"):
        session_budgets_from_mandate(mandate)
    assert BudgetType.DATA_EXPORT_BYTES not in SUPPORTED_BUDGET_TYPES
