"""Taint / provenance tracking — the principled defense against injection at the
action layer.

Prompt injection, hidden-Unicode instructions, and poisoned tool descriptions
all share one mechanic: untrusted content that entered after the goal was sealed
becomes the justification for a real action. Rather than trying to detect the
malicious *text*, we track the *trust* of what drives each action. An action
whose justification traces back to untrusted context, and which does something
consequential the sealed goal never asked for, is exactly the shape to escalate.

The tracker is a mechanism, not a policy: it labels actions, and the detector
decides what to do with the label (feature into scoring, force escalation for
high-side-effect tainted actions, and so on).
"""
from __future__ import annotations

from dataclasses import dataclass

from agentauth.capabilities.monitor.action import (
    Action,
    ContextItem,
    Trajectory,
    TrustLevel,
)

# Verbs whose misuse is consequential enough that taint should force escalation.
_CONSEQUENTIAL_VERBS = frozenset(
    {"send", "transfer", "delete", "post", "write", "update", "create", "pay"}
)


@dataclass(frozen=True)
class TaintVerdict:
    """Whether an action is driven by untrusted, post-seal context."""

    tainted: bool
    consequential: bool
    untrusted_sources: tuple[str, ...] = ()

    @property
    def escalate(self) -> bool:
        """A tainted action that also does something consequential is high risk."""
        return self.tainted and self.consequential


def context_item_from_content(
    item_id: str,
    text: str,
    *,
    step: int = 0,
    default_trust: TrustLevel = TrustLevel.TRUSTED,
) -> ContextItem:
    """Build a context item, downgrading to UNTRUSTED if the content carries
    injection-delivery markers (hidden Unicode, homoglyphs, bidi overrides).

    This is the bridge from ``hardening.input_hardening`` to the taint layer:
    content that needed hardening should not silently justify a consequential
    action, so it enters the trajectory as untrusted.
    """
    from agentauth.capabilities.hardening.input_hardening import scan

    markers = scan(text)
    trust = TrustLevel.UNTRUSTED if markers else default_trust
    summary = ("injection-markers: " + ", ".join(markers)) if markers else ""
    return ContextItem(item_id=item_id, trust=trust, introduced_at_step=step, summary=summary)


class TaintTracker:
    """Propagates trust from context items into the actions they justify."""

    def __init__(self, context: list[ContextItem] | None = None) -> None:
        self._items: dict[str, ContextItem] = {}
        for item in context or []:
            self._items[item.item_id] = item

    @classmethod
    def from_trajectory(cls, traj: Trajectory) -> "TaintTracker":
        return cls(context=traj.context)

    def observe(self, item: ContextItem) -> None:
        """Register a context item as it enters the agent's working set."""
        self._items[item.item_id] = item

    def assess(self, action: Action) -> TaintVerdict:
        untrusted = tuple(
            src
            for src in action.derived_from
            if self._items.get(src) is not None
            and self._items[src].trust is TrustLevel.UNTRUSTED
            and self._items[src].introduced_at_step <= action.step
        )
        consequential = action.verb.lower() in _CONSEQUENTIAL_VERBS
        return TaintVerdict(
            tainted=bool(untrusted),
            consequential=consequential,
            untrusted_sources=untrusted,
        )
