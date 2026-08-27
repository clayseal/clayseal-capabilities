"""Atomic tool-call budget + write-tool fail-closed + strict-lease coverage."""

from __future__ import annotations

import threading

from clayseal.capabilities.scoping.tools.models import ToolCapabilityLease
from clayseal.capabilities.scoping.tools.tool_call_budget import (
    ToolCallBudget,
    ToolCallBudgetConfig,
)
from clayseal.capabilities.scoping.tools.tool_enforcement import check_tool_call_allowed
from clayseal.capabilities.scoping.tools.tool_lease_enforcement import (
    commit_tool_call_budget,
    release_tool_call_budget,
    reserve_tool_call_budget,
    tool_capability_lease_violations,
)
from clayseal.core.runtime import SideEffectLevel


def _budget(limit: int = 1) -> ToolCallBudget:
    return ToolCallBudget(
        config=ToolCallBudgetConfig(
            high_risk_tools=frozenset({"issue_payroll_bonus"}),
            high_risk_max_calls_per_target=limit,
        )
    )


def _lease() -> ToolCapabilityLease:
    return ToolCapabilityLease(
        query_id="q",
        snapshot_id="s",
        expected_tools={"issue_payroll_bonus"},
        expected_targets={"issue_payroll_bonus": {"emp_1"}},
    )


# --- Fix 2: atomic reserve/commit/release --------------------------------- #


def test_reserve_holds_slot_until_committed_or_released():
    b = _budget(limit=1)
    r1 = b.reserve("issue_payroll_bonus", "emp_1")
    assert r1.allowed
    # The single slot is now reserved; a second reserve is denied.
    r2 = b.reserve("issue_payroll_bonus", "emp_1")
    assert not r2.allowed and r2.reason == "target_call_budget_exhausted"
    # Releasing r1 frees the slot again.
    r1.release()
    r3 = b.reserve("issue_payroll_bonus", "emp_1")
    assert r3.allowed
    r3.commit()
    assert b.calls[("issue_payroll_bonus", "emp_1")] == 1


def test_parallel_reserve_respects_limit():
    b = _budget(limit=3)
    results: list[bool] = []
    lock = threading.Lock()
    barrier = threading.Barrier(20)

    def worker():
        barrier.wait()
        r = b.reserve("issue_payroll_bonus", "emp_1")
        with lock:
            results.append(r.allowed)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 3


def test_reserve_wiring_commit_and_release():
    b = _budget(limit=1)
    res = reserve_tool_call_budget(
        b,
        tool_name="issue_payroll_bonus",
        arguments={"employee_id": "emp_1"},
        side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
    )
    assert res is not None and res.allowed
    res.commit()
    assert b.calls[("issue_payroll_bonus", "emp_1")] == 1
    # A read-only tool has nothing to reserve.
    assert (
        reserve_tool_call_budget(
            b,
            tool_name="recall_notes",
            arguments={},
            side_effect=SideEffectLevel.READ_ONLY,
        )
        is None
    )
    release_tool_call_budget(None)  # safe on None


# --- Fix 6: write-tool fail-closed on unresolved target -------------------- #


def test_check_tool_call_allowed_fails_closed_for_write_without_target():
    lease = _lease()
    allowed, reason = check_tool_call_allowed("issue_payroll_bonus", None, lease, write=True)
    assert not allowed and reason == "target_unresolved"
    # Reads keep the permissive "no target" behavior.
    ok, reason2 = check_tool_call_allowed("issue_payroll_bonus", None, lease, write=False)
    assert ok and reason2 == "no_target_arg"


def test_lease_violation_when_write_target_unresolvable():
    lease = _lease()
    violations = tool_capability_lease_violations(
        lease,
        _budget(),
        tool_name="issue_payroll_bonus",
        arguments={"note": "no employee id here"},  # target cannot be extracted
        side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
        resource_ref=None,
    )
    assert violations and "target_unresolved" in violations[0]


def test_commit_consumes_sentinel_for_unresolved_write_target():
    b = _budget(limit=5)
    commit_tool_call_budget(
        b,
        tool_name="issue_payroll_bonus",
        arguments={"note": "no id"},
        side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
    )
    assert b.calls[("issue_payroll_bonus", "<untargeted:issue_payroll_bonus>")] == 1


# --- Fix 10: strict lease-absent ------------------------------------------ #


def test_lease_absent_permissive_by_default():
    assert (
        tool_capability_lease_violations(
            None,
            None,
            tool_name="issue_payroll_bonus",
            arguments={"employee_id": "emp_1"},
            side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
            resource_ref=None,
        )
        == []
    )


def test_lease_absent_strict_fails_closed_for_write():
    violations = tool_capability_lease_violations(
        None,
        None,
        tool_name="issue_payroll_bonus",
        arguments={"employee_id": "emp_1"},
        side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
        resource_ref=None,
        strict=True,
    )
    assert violations and "required but absent" in violations[0]
    # A read stays permissive even in strict mode.
    assert (
        tool_capability_lease_violations(
            None,
            None,
            tool_name="recall_notes",
            arguments={},
            side_effect=SideEffectLevel.READ_ONLY,
            resource_ref=None,
            strict=True,
        )
        == []
    )
