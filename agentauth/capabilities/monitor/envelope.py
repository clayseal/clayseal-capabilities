"""Layer 1: typed goal envelope, structural plausibility, no model, no cost.

Compiles the sealed ``GoalSpec`` into the set of action shapes plausibly needed
to accomplish it: which resource classes may be touched, which verbs are
expected, and (when known) which tools are in play. An action outside the
envelope is flagged structurally and interpretably, before any learned scorer
runs. This is the cheap tier of the escalating-cost design: most actions are
in-envelope and never reach the expensive layers.

The envelope is deliberately a *superset* of what the L2 lease authorizes: it
reflects "plausible for this goal," not "cryptographically permitted." The two
compose. A structurally in-envelope action can still be denied by the lease, and
a lease-permitted action can still be structurally surprising and escalated.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from agentauth.capabilities.monitor.action import Action
from agentauth.capabilities.monitor.surface import (
    in_surface,
    resource_readings,
    surface_from,
)
from agentauth.capabilities.scoping.goal import GoalSpec

# Verbs an agent may use when the goal does not narrow them further.
_DEFAULT_READ_VERBS = frozenset({"read", "get", "list", "search", "view"})
_WRITE_VERBS = frozenset({"write", "create", "update", "delete", "send", "transfer", "post"})


@dataclass
class TypedGoalEnvelope:
    """Structural envelope compiled from a sealed goal."""

    allowed_resource_classes: frozenset[str]
    allowed_verbs: frozenset[str]
    allowed_tools: frozenset[str]
    read_only: bool

    @classmethod
    def from_goal(cls, goal: GoalSpec) -> TypedGoalEnvelope:
        intent = goal.structured_intent or {}
        # `surface_from` is the one reading used on both sides of every
        # membership test, and it drops the blank classes that would make an
        # empty surface look populated. See `monitor/surface.py`.
        resource_classes = set(surface_from(goal.allow_resources))
        # Explicit files imply a repo/file surface even if not listed as resources.
        if goal.explicit_allow_files():
            resource_classes.update({"repo", "file"})

        verbs = set(_DEFAULT_READ_VERBS)
        write_allowed = bool(
            goal.allow_agent_memory_writes
            or intent.get("allow_writes")
            or intent.get("mutating")
        )
        declared_verbs = intent.get("verbs")
        if isinstance(declared_verbs, (list, tuple, set)):
            verbs = {str(v).lower() for v in declared_verbs}
            write_allowed = bool(verbs & _WRITE_VERBS)
        elif write_allowed:
            verbs |= _WRITE_VERBS

        tools = intent.get("tools")
        allowed_tools = (
            frozenset(str(t) for t in tools)
            if isinstance(tools, (list, tuple, set))
            else frozenset()
        )
        return cls(
            allowed_resource_classes=frozenset(resource_classes),
            allowed_verbs=frozenset(verbs),
            allowed_tools=allowed_tools,
            read_only=not write_allowed,
        )

    def assess(self, action: Action, *,
               resources_comparable: bool = True) -> EnvelopeVerdict:
        """Structural verdict for one action.

        `resources_comparable` is the caller's answer to "has this session ever
        spoken the surface's vocabulary". It defaults to True so a caller with
        no trajectory behaves as before; a caller that has one should pass
        `monitor.surface.surface_is_comparable`, because a surface that has
        never matched cannot tell a violation from a naming convention. See
        `monitor/surface.py` for what this cost when it was missing.
        """
        reasons: list[str] = []
        if (self.allowed_resource_classes and resources_comparable
                and not in_surface(action, self.allowed_resource_classes)):
            readings = resource_readings(action)
            rc = readings[0] if readings else ""
            reasons.append(f"resource-class {rc!r} not in goal envelope")
        if self.allowed_verbs and action.verb.lower() not in self.allowed_verbs:
            reasons.append(f"verb {action.verb!r} not expected for goal")
        if self.allowed_tools and action.tool not in self.allowed_tools:
            reasons.append(f"tool {action.tool!r} not named by goal")
        if self.read_only and action.verb.lower() in _WRITE_VERBS:
            reasons.append("mutating action under a read-only goal")
        return EnvelopeVerdict(in_envelope=not reasons, reasons=tuple(reasons))


@dataclass(frozen=True)
class EnvelopeVerdict:
    in_envelope: bool
    reasons: tuple[str, ...] = field(default_factory=tuple)
