"""What entities exist, and which tools act on them.

`ToolSpec` describes a tool, `EntityRecord` an object it can act on, and
`ToolEntityIndex` is the catalogue a tool lease is scoped against — the analogue
of the repository chunk index on the file side.

The index is built from declarations rather than from observed traffic. Scoping
to what a session has already done would let the first call widen the grant for
every call after it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from clayseal.core.hash_util import hash_canonical_json
from clayseal.core.runtime import SideEffectLevel


@dataclass(frozen=True)
class ToolSpec:
    """One registered tool, as known to a gateway/session (parallel to RepoChunk).

    ``trust_tier`` matters more than it looks: a shadow/legacy connector's
    description can describe itself using the same vocabulary as the tool
    it substitutes for ("bonus payment", etc.), so text-relevance matching
    alone cannot be trusted to keep it out of scope. Only "primary" tools
    are eligible for automatic token-overlap relevance matching against a
    goal; a "shadow" tool can only ever enter a lease's ``expected_tools``
    via an explicit allow, never by looking relevant.
    """

    name: str
    description: str
    owner_role: str
    side_effect_level: SideEffectLevel
    target_arg_keys: tuple[str, ...] = ()
    trust_tier: str = "primary"  # "primary" | "shadow"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "owner_role": self.owner_role,
            "side_effect_level": self.side_effect_level.value,
            "target_arg_keys": list(self.target_arg_keys),
            "trust_tier": self.trust_tier,
        }


@dataclass(frozen=True)
class EntityRecord:
    """One resolvable target entity (employee, group, device, ...)."""

    entity_id: str
    entity_kind: str
    display_name: str
    aliases: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_kind": self.entity_kind,
            "display_name": self.display_name,
            "aliases": list(self.aliases),
            "tags": list(self.tags),
        }


@dataclass
class ToolEntityIndex:
    """Frozen snapshot of registered tools + resolvable entities for one session."""

    snapshot_id: str
    tools: list[ToolSpec] = field(default_factory=list)
    entities: list[EntityRecord] = field(default_factory=list)
    membership_edges: list[tuple[str, str]] = field(default_factory=list)

    def tools_by_name(self) -> dict[str, ToolSpec]:
        return {tool.name: tool for tool in self.tools}

    def entities_by_id(self) -> dict[str, EntityRecord]:
        return {entity.entity_id: entity for entity in self.entities}

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "tools": [tool.to_dict() for tool in self.tools],
            "entities": [entity.to_dict() for entity in self.entities],
            "membership_edges": [{"from": src, "to": dst} for src, dst in self.membership_edges],
        }


def build_tool_entity_index(
    *,
    tools: list[ToolSpec],
    entities: list[EntityRecord],
    membership_edges: list[tuple[str, str]],
) -> ToolEntityIndex:
    snapshot_id = hash_canonical_json(
        {
            "tools": sorted((tool.to_dict() for tool in tools), key=lambda item: item["name"]),
            "entities": sorted(
                (entity.to_dict() for entity in entities), key=lambda item: item["entity_id"]
            ),
            "membership_edges": sorted(membership_edges),
        }
    )
    return ToolEntityIndex(
        snapshot_id=snapshot_id,
        tools=list(tools),
        entities=list(entities),
        membership_edges=list(membership_edges),
    )
