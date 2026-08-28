"""Capability operations contract, canonical home: ``clayseal.core.operations``.

Re-export so ``clayseal.capabilities.operations`` remains a valid import path.
"""

from __future__ import annotations

from clayseal.core.operations import (
    MCP_TOOL_RESOURCE,
    CapabilityAuthorizer,
    CapabilityOperation,
    capability_allows,
    capability_subset,
    mcp_tool_capability,
    normalize_capabilities,
    operation_for_action,
    operation_for_mcp_tool,
)

__all__ = [
    "MCP_TOOL_RESOURCE",
    "CapabilityAuthorizer",
    "CapabilityOperation",
    "capability_allows",
    "capability_subset",
    "mcp_tool_capability",
    "normalize_capabilities",
    "operation_for_action",
    "operation_for_mcp_tool",
]
