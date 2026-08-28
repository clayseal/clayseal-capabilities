"""`ToolCapabilityLease`: the tool-side analogue of a file lease.

Where a `CapabilityLease` narrows which paths a session may touch, this narrows
which tools it may call and which entities it may call them against. The two are
separate types because the questions differ: a path is hierarchical and a tool
target usually is not.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCapabilityLease:
    """Tool + target-entity expectations minted for one goal (parallel to CapabilityLease)."""

    query_id: str
    snapshot_id: str
    seed_evidence: list[dict[str, Any]] = field(default_factory=list)
    expected_tools: set[str] = field(default_factory=set)
    expected_targets: dict[str, set[str]] = field(default_factory=dict)
    explicit_allow_targets: dict[str, set[str]] = field(default_factory=dict)
    metric_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_id": self.query_id,
            "snapshot_id": self.snapshot_id,
            "seed_evidence": list(self.seed_evidence),
            "expected_tools": sorted(self.expected_tools),
            "expected_targets": {
                tool: sorted(targets) for tool, targets in sorted(self.expected_targets.items())
            },
            "explicit_allow_targets": {
                tool: sorted(targets)
                for tool, targets in sorted(self.explicit_allow_targets.items())
            },
            "metric_id": self.metric_id,
        }

    def resource_scope_entries(self) -> list[str]:
        """Entries for ``AuthorityContext.resource_scope``, mirroring
        ``CapabilityLease.resource_scope_entries()``'s ``repo://`` entries."""
        entries: list[str] = []
        for tool, targets in sorted(self.expected_targets.items()):
            for target in sorted(targets):
                entries.append(f"entity://{tool}/{target}")
        for tool in sorted(self.expected_tools):
            if tool not in self.expected_targets:
                entries.append(f"entity://{tool}")
        return sorted(set(entries))
