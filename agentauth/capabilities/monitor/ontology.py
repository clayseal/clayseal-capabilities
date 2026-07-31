"""Lightweight tool ontology — preconditions, effects, and reversibility.

The feasibility check needs to know, for each tool, what facts it requires to
run (preconditions), what facts it makes true or false (effects), and whether an
effect can be undone. This is the classical planning operator model (PDDL), kept
deliberately small: facts are opaque string labels, so an integrator declares
only what the feasibility reasoner needs, not a full domain theory.

An ontology is optional. Without it, the intent envelope falls back to
membership and order conformance; with it, the envelope can tell that an action
has steered the mission somewhere the goal can no longer be reached from.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolSpec:
    tool: str
    preconditions: frozenset[str] = frozenset()  # facts required to run
    establishes: frozenset[str] = frozenset()    # facts set true (add effects)
    destroys: frozenset[str] = frozenset()       # facts set false (delete effects)
    reversible: bool = True                       # can a destroyed fact be re-achieved

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "preconditions": sorted(self.preconditions),
            "establishes": sorted(self.establishes),
            "destroys": sorted(self.destroys),
            "reversible": self.reversible,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ToolSpec":
        return cls(
            tool=str(raw["tool"]),
            preconditions=frozenset(str(x) for x in raw.get("preconditions", [])),
            establishes=frozenset(str(x) for x in raw.get("establishes", [])),
            destroys=frozenset(str(x) for x in raw.get("destroys", [])),
            reversible=bool(raw.get("reversible", True)),
        )


@dataclass
class ToolOntology:
    specs: dict[str, ToolSpec] = field(default_factory=dict)

    def spec(self, tool: str) -> ToolSpec | None:
        return self.specs.get(tool)

    def to_dict(self) -> list[dict[str, Any]]:
        return [s.to_dict() for s in self.specs.values()]

    @classmethod
    def from_dict(cls, raw: Any) -> "ToolOntology":
        specs: dict[str, ToolSpec] = {}
        for item in raw or []:
            if isinstance(item, dict) and item.get("tool"):
                spec = ToolSpec.from_dict(item)
                specs[spec.tool] = spec
        return cls(specs=specs)
