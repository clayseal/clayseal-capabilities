"""Is this tool call inside the tool lease?

The tool-side counterpart of `scoping/enforcement.py`: one question, asked after
the arguments have been normalised into a target by
`tool_lease_enforcement.target_entity_from_arguments`.
"""
from __future__ import annotations

from clayseal.capabilities.scoping.tools.models import ToolCapabilityLease


def check_tool_call_allowed(
    tool_name: str,
    target_entity: str | None,
    lease: ToolCapabilityLease,
    *,
    write: bool = False,
) -> tuple[bool, str]:
    """Mirrors ``check_repo_path_allowed`` for tool/target scope instead of file paths.

    ``write`` fails closed: for a write/mutating tool a target that could not be
    extracted is a VIOLATION (``target_unresolved``) rather than a free pass, so
    an unparseable payload can't slip an unscoped write past the lease.
    """
    allowed_targets = lease.explicit_allow_targets.get(tool_name)
    if allowed_targets and target_entity in allowed_targets:
        return True, "explicit_allow"

    if tool_name not in lease.expected_tools:
        return False, "tool_out_of_scope"

    if target_entity is None:
        if write:
            return False, "target_unresolved"
        return True, "no_target_arg"

    if target_entity not in lease.expected_targets.get(tool_name, set()):
        return False, "target_out_of_scope"

    return True, "lease_allowlist"
