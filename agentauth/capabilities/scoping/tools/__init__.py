"""Tool-call capability leasing + session drift detection (parallel to the
file-scoping system in agentauth.capabilities.scoping)."""

from agentauth.capabilities.scoping.tools.entity_index import (
    EntityRecord,
    ToolEntityIndex,
    ToolSpec,
    build_tool_entity_index,
)
from agentauth.capabilities.scoping.tools.entity_match import EntityMatch, resolve_target_entities
from agentauth.capabilities.scoping.tools.models import ToolCapabilityLease
from agentauth.capabilities.scoping.tools.target_closure import (
    TargetClosure,
    TargetClosurePolicy,
    compute_target_closure,
)
from agentauth.capabilities.scoping.tools.tool_call_budget import (
    ToolCallBudget,
    ToolCallBudgetConfig,
    ToolCallReservation,
)
from agentauth.capabilities.scoping.tools.tool_capability_scope import (
    build_tool_capability_lease,
    score_targets_for_goal,
)
from agentauth.capabilities.scoping.tools.tool_enforcement import check_tool_call_allowed
from agentauth.capabilities.scoping.tools.tool_lease_enforcement import (
    commit_tool_call_budget,
    release_tool_call_budget,
    reserve_tool_call_budget,
    target_entity_from_arguments,
    tool_capability_lease_violations,
)

__all__ = [
    "EntityMatch",
    "EntityRecord",
    "TargetClosure",
    "TargetClosurePolicy",
    "ToolCallBudget",
    "ToolCallBudgetConfig",
    "ToolCallReservation",
    "ToolCapabilityLease",
    "ToolEntityIndex",
    "ToolSpec",
    "build_tool_capability_lease",
    "build_tool_entity_index",
    "check_tool_call_allowed",
    "commit_tool_call_budget",
    "compute_target_closure",
    "release_tool_call_budget",
    "reserve_tool_call_budget",
    "resolve_target_entities",
    "score_targets_for_goal",
    "target_entity_from_arguments",
    "tool_capability_lease_violations",
]
