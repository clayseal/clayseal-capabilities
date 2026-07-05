from __future__ import annotations

from typing import Any

from agentauth.core.runtime import SideEffectLevel
from agentauth.capabilities.scoping.enforcement import check_repo_path_allowed
from agentauth.capabilities.scoping.models import CapabilityLease
from agentauth.capabilities.task_scope import action_path_candidates

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
) -> list[str]:
    """Fail closed when an active lease denies the resolved repo path."""
    if lease is None:
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
