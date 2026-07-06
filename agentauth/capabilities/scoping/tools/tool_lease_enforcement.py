from __future__ import annotations

import os
from typing import Any

from agentauth.core.runtime import SideEffectLevel
from agentauth.capabilities.scoping.tools.models import ToolCapabilityLease
from agentauth.capabilities.scoping.tools.tool_call_budget import ToolCallBudget, ToolCallReservation
from agentauth.capabilities.scoping.tools.tool_enforcement import check_tool_call_allowed

_TARGET_ARG_KEYS: dict[str, tuple[str, ...]] = {
    "issue_payroll_bonus": ("employee_id",),
    "update_job_title": ("employee_id",),
    "grant_app_access": ("employee_id",),
    "raise_spend_card_limit": ("employee_id", "card_id"),
    "update_payment_profile": ("employee_id",),
    "share_rpass_vault_secret": ("target_employee_id", "target_supergroup_id"),
    "lock_device": ("employee_id", "device_id"),
    "legacy_process_bonus_payment": ("employee_id",),
}
_FALLBACK_TARGET_ARG_KEYS = ("employee_id", "target_employee_id", "device_id", "card_id", "entity_id")

# Opt-in strict mode: when a lease is REQUIRED but absent for a gated
# (write/mutating) action, return a violation instead of failing open. Kept
# opt-in (default off, env-overridable) so deployments that use leases only for
# some sessions keep working; production callers that gate every write on a
# lease should set AGENTAUTH_LEASE_STRICT=1 (or pass strict=True).
LEASE_STRICT_ENV = "AGENTAUTH_LEASE_STRICT"


def _strict_default() -> bool:
    return os.getenv(LEASE_STRICT_ENV, "").strip().lower() in {"1", "true", "yes"}


def target_entity_from_arguments(tool_name: str, arguments: dict[str, Any]) -> str | None:
    for key in _TARGET_ARG_KEYS.get(tool_name, _FALLBACK_TARGET_ARG_KEYS):
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _untargeted(tool_name: str) -> str:
    """Sentinel target so an unresolved-target write still consumes budget
    (keyed on the tool) rather than silently escaping the ledger."""
    return f"<untargeted:{tool_name}>"


def _is_write_tool(side_effect: SideEffectLevel) -> bool:
    """Anything with a real side effect is budget-tracked -- deliberately
    inclusive (non-read) rather than an allowlist of specific levels. A
    real HR/payroll action can land as BOUNDED_WRITE, EXTERNAL_SIDE_EFFECT,
    or PRIVILEGED_MUTATION depending on how a given fixture/product
    classifies it; excluding any of those by omission would silently skip
    budget tracking for real writes, exactly the failure mode this
    mechanism exists to prevent."""
    return side_effect != SideEffectLevel.READ_ONLY


def tool_capability_lease_violations(
    lease: ToolCapabilityLease | None,
    budget: ToolCallBudget | None,
    *,
    tool_name: str,
    arguments: dict[str, Any],
    side_effect: SideEffectLevel,
    resource_ref: str | None,
    strict: bool | None = None,
) -> list[str]:
    """Pure check, no mutation -- safe to call from any pre-execution pass,
    including a monitoring/dry-run one. Budget consumption is a separate,
    explicit step (``commit_tool_call_budget``/``reserve_tool_call_budget``)
    fired only once a call is confirmed non-blocked by every other check
    (sandbox governor included), since ``_pre_execution_violations`` runs before
    the governor's own commit-token/step-up checks and a call can still be
    blocked after this function returns clean.

    ``strict`` (default from ``AGENTAUTH_LEASE_STRICT``) fails closed on a gated
    write when NO lease is present: without a lease there is nothing to bound
    the write, so a strict deployment treats "lease required but missing" as a
    violation rather than a free pass.
    """
    if strict is None:
        strict = _strict_default()

    if lease is None:
        if strict and _is_write_tool(side_effect):
            return [
                f"tool capability lease required but absent (strict): tool={tool_name!r}"
            ]
        return []

    # Read-only tools are informational in the lease (expected_tools/
    # seed_evidence carry them for audit) but are never enforced -- over
    # -permitting a read is cheap, and legitimate exploratory reads
    # routinely fall outside what token-relevance matching against the
    # original goal predicted was needed. Confirmed by a live run: a
    # perfectly ordinary recall_notes call got denied as tool_out_of_scope
    # before this exemption existed, which is exactly the over-blocking
    # this mechanism must not cause. Enforcement is reserved for writes,
    # where the actual exploit class (decomposition, shadow substitution)
    # lives.
    if not _is_write_tool(side_effect):
        return []

    target_entity = target_entity_from_arguments(tool_name, arguments)
    allowed, reason = check_tool_call_allowed(tool_name, target_entity, lease, write=True)
    if not allowed:
        return [
            f"tool capability lease {reason}: tool={tool_name!r} target={target_entity!r}"
        ]

    if budget is not None and target_entity is not None:
        would_allow, budget_reason = budget.would_allow(
            tool_name, target_entity, idempotency_key=_idempotency_key(arguments)
        )
        if not would_allow:
            return [
                f"tool call budget {budget_reason}: tool={tool_name!r} target={target_entity!r}"
            ]

    return []


def _idempotency_key(arguments: dict[str, Any]) -> str | None:
    value = arguments.get("_idempotency_key")
    return value.strip() if isinstance(value, str) and value.strip() else None


def reserve_tool_call_budget(
    budget: ToolCallBudget | None,
    *,
    tool_name: str,
    arguments: dict[str, Any],
    side_effect: SideEffectLevel,
) -> ToolCallReservation | None:
    """Atomically reserve a call slot at check-time (the race-free gate).

    Returns the reservation the caller must later finalize with ``.commit()``
    (call confirmed) or ``.release()`` (call blocked/failed); ``None`` when
    there is nothing to reserve (no budget, or a read-only tool). An unresolved
    target on a write reserves against a per-tool sentinel so budget is still
    consumed rather than escaping the ledger."""
    if budget is None or not _is_write_tool(side_effect):
        return None
    target_entity = target_entity_from_arguments(tool_name, arguments) or _untargeted(tool_name)
    return budget.reserve(tool_name, target_entity, idempotency_key=_idempotency_key(arguments))


def release_tool_call_budget(reservation: ToolCallReservation | None) -> None:
    """Roll back a reservation from :func:`reserve_tool_call_budget` (call
    blocked/failed after reserving). Safe on ``None``."""
    if reservation is not None:
        reservation.release()


def commit_tool_call_budget(
    budget: ToolCallBudget | None,
    *,
    tool_name: str,
    arguments: dict[str, Any],
    side_effect: SideEffectLevel,
) -> None:
    """Consume budget for a call already confirmed non-blocked (legacy direct
    path). Must not be called from any path where the call might still be denied
    afterward. An unresolved target on a write consumes a per-tool sentinel slot
    so the write is still counted rather than escaping the ledger."""
    if budget is None or not _is_write_tool(side_effect):
        return
    target_entity = target_entity_from_arguments(tool_name, arguments) or _untargeted(tool_name)
    budget.commit(tool_name, target_entity, idempotency_key=_idempotency_key(arguments))
