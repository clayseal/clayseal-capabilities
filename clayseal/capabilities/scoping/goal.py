"""The sealed goal: what the session was asked to do.

`GoalSpec` is the trusted input everything downstream narrows against. It is
captured before any tool output can reach it, which is the property that makes
declassification and replanning safe: an injected instruction arriving in a tool
result cannot nominate a sink or widen a scope, because the goal it would have to
change was already sealed.

Small on purpose. Anything richer would be a place for untrusted text to enter.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class GoalSpec:
    """Trusted control-plane goal for one lease (DP-17)."""

    query_id: str
    summary: str
    allow_resources: list[str] = field(default_factory=list)
    allow_agent_memory_writes: bool = False
    structured_intent: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> GoalSpec:
        intent = raw.get("intent") if isinstance(raw.get("intent"), dict) else {}
        allow = intent.get("allow_resources") if isinstance(intent, dict) else raw.get("allow_resources")
        if not isinstance(allow, list):
            allow = []
        allow_memory = raw.get("allow_agent_memory_writes")
        if allow_memory is None and isinstance(intent, dict):
            allow_memory = intent.get("allow_agent_memory_writes")
        return cls(
            query_id=str(raw.get("query_id") or raw.get("goal_id") or ""),
            summary=str(raw.get("summary") or raw.get("text") or ""),
            allow_resources=[str(item) for item in allow],
            allow_agent_memory_writes=bool(allow_memory),
            structured_intent=dict(intent) if isinstance(intent, dict) else {},
        )

    def explicit_allow_files(self) -> set[str]:
        files: set[str] = set()
        for resource in self.allow_resources:
            if resource.startswith("repo://"):
                files.add(resource.removeprefix("repo://"))
            elif resource.startswith("file:"):
                files.add(resource.removeprefix("file:"))
            elif not resource.startswith("net:"):
                files.add(resource.lstrip("/"))
        return files
