from __future__ import annotations

from agentauth.capabilities.scoping.tools.models import ToolCapabilityLease


def check_tool_call_allowed(
    tool_name: str,
    target_entity: str | None,
    lease: ToolCapabilityLease,
) -> tuple[bool, str]:
    """Mirrors ``check_repo_path_allowed`` for tool/target scope instead of file paths."""
    allowed_targets = lease.explicit_allow_targets.get(tool_name)
    if allowed_targets and target_entity in allowed_targets:
        return True, "explicit_allow"

    if tool_name not in lease.expected_tools:
        return False, "tool_out_of_scope"

    if target_entity is None:
        return True, "no_target_arg"

    if target_entity not in lease.expected_targets.get(tool_name, set()):
        return False, "target_out_of_scope"

    return True, "lease_allowlist"
