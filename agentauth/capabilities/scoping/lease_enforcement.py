from __future__ import annotations

import os
from typing import Any

from agentauth.capabilities.scoping.enforcement import check_repo_path_allowed
from agentauth.capabilities.scoping.models import CapabilityLease
from agentauth.capabilities.task_scope import action_path_candidates
from agentauth.core.runtime import SideEffectLevel

# See tool_lease_enforcement.LEASE_STRICT_ENV -- shared opt-in strict flag.
LEASE_STRICT_ENV = "AGENTAUTH_LEASE_STRICT"


def _strict_default() -> bool:
    explicit = os.getenv(LEASE_STRICT_ENV, "").strip().lower()
    if explicit in {"1", "true", "yes", "on"}:
        return True
    if explicit in {"0", "false", "no", "off"}:
        return False
    from agentauth.core.production import fail_closed

    return fail_closed()

_WRITE_TOOL_MARKERS = (
    "write",
    "edit",
    "patch",
    "create",
    "delete",
    "remove",
    "rename",
    "move",
    "apply",
)


def file_path_from_arguments(arguments: dict[str, Any]) -> str | None:
    for key in ("path", "file_path", "filepath", "target", "file"):
        value = arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def is_write_tool(tool_name: str, side_effect: SideEffectLevel) -> bool:
    if side_effect in {
        SideEffectLevel.BOUNDED_WRITE,
        SideEffectLevel.PRIVILEGED_MUTATION,
    }:
        return True
    lowered = tool_name.lower()
    return any(marker in lowered for marker in _WRITE_TOOL_MARKERS)


def capability_lease_violations(
    lease: CapabilityLease | None,
    *,
    tool_name: str,
    arguments: dict[str, Any],
    side_effect: SideEffectLevel,
    resource_ref: str | None,
    strict: bool | None = None,
) -> list[str]:
    """Fail closed when an active lease denies the resolved repo path.

    ``strict`` (default from ``AGENTAUTH_LEASE_STRICT``) also fails closed when
    NO lease is present for a gated write: without a lease there is nothing to
    bound the write, so a strict deployment reports a violation rather than
    letting the write through unscoped.
    """
    if strict is None:
        strict = _strict_default()

    if lease is None:
        if strict and is_write_tool(tool_name, side_effect):
            return [
                f"capability lease required but absent (strict): "
                f"tool={tool_name!r}, resource_ref={resource_ref!r}"
            ]
        return []

    paths = action_path_candidates(resource_ref=resource_ref)
    if not paths:
        fallback = file_path_from_arguments(arguments)
        if fallback:
            paths = [fallback.lstrip("/")]
    if not paths:
        return []

    write = is_write_tool(tool_name, side_effect)
    violations: list[str] = []
    for path in paths:
        allowed, reason = check_repo_path_allowed(path, lease, write=write)
        if not allowed:
            violations.append(
                f"capability lease {reason}: {path!r} "
                f"(tool={tool_name!r}, write={write})"
            )
    return violations
