from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agentauth.core.runtime import ActionDescriptor

MCP_TOOL_RESOURCE = "mcp_tool"


@dataclass(frozen=True)
class CapabilityOperation:
    """Canonical ``resource:action`` operation authorized by a capability token."""

    resource: str
    action: str

    def label(self) -> str:
        return f"{self.resource}:{self.action}"


CapabilityAuthorizer = Callable[[str, str], dict[str, Any]]


def normalize_capabilities(capabilities: list[dict[str, Any]] | None) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for raw in capabilities or []:
        resource = str(raw.get("resource", "")).strip()
        action = str(raw.get("action", "")).strip()
        if resource and action:
            out.append({"resource": resource, "action": action})
    return out


def mcp_tool_capability(tool_name: str) -> dict[str, str]:
    return {"resource": MCP_TOOL_RESOURCE, "action": tool_name}


def operation_for_mcp_tool(tool_name: str) -> CapabilityOperation:
    return CapabilityOperation(MCP_TOOL_RESOURCE, tool_name)


def _action_leaf(action_name: str) -> str:
    text = action_name.strip()
    if "/" in text:
        return text.rsplit("/", 1)[-1]
    if "." in text:
        return text.rsplit(".", 1)[-1]
    return text


def operation_for_action(action: ActionDescriptor) -> CapabilityOperation:
    """Map an execution action to the operation shape used in Biscuit tokens."""
    if action.action_category == "mcp_tool_call" and action.resource_type == MCP_TOOL_RESOURCE:
        return CapabilityOperation(MCP_TOOL_RESOURCE, _action_leaf(action.action_name))
    resource = action.resource_type or action.action_category or "action"
    return CapabilityOperation(resource, _action_leaf(action.action_name))


def capability_allows(
    capabilities: list[dict[str, Any]] | None,
    resource: str,
    action: str,
) -> bool:
    """Return true when capability rules authorize ``resource:action``.

    This mirrors the Biscuit authorizer's current semantics: resource must match
    exactly, while action may be exact or ``"*"``.
    """
    for cap in normalize_capabilities(capabilities):
        if cap["resource"] != resource:
            continue
        if cap["action"] == "*" or cap["action"] == action:
            return True
    return False


def capability_subset(
    child: list[dict[str, Any]] | None,
    parent: list[dict[str, Any]] | None,
    label: str,
) -> list[str]:
    parent_caps = normalize_capabilities(parent)
    extras = [
        cap for cap in normalize_capabilities(child)
        if not capability_allows(parent_caps, cap["resource"], cap["action"])
    ]
    if not extras:
        return []
    rendered = [f"{cap['resource']}:{cap['action']}" for cap in extras]
    parent_rendered = [f"{cap['resource']}:{cap['action']}" for cap in parent_caps]
    return [f"{label}: capabilities {rendered} exceed parent capabilities {parent_rendered}"]
