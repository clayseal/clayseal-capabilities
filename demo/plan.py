"""The sealed intent envelope for the demo's goal.

`classify_verb` and `verb_class_order` are imported rather than copied. Both are
security-relevant: the first decides whether a tool is an acquisition or an
effect, the second derives the "gather before act" partial order the conformance
check enforces. A second copy here could drift from the one the broker and the
benchmarks use, and the two disagreeing is precisely the failure this demo
exists to make visible. Neither import pulls anything heavy (stdlib only).

WHY NOT `IntentEnvelope.from_goal`: it leaves `phase_order=None`, which means a
legacy TOTAL order, every phase must follow every lower-indexed one. With
per-tool phases, reading T-1003 after T-1005 would register as OUT_OF_ORDER and
the demo would blame the injection for an artifact of its own plan encoding.
`verb_class_order` gives a real partial order (reads unordered among themselves,
effects likewise), derived from trusted tool metadata rather than model text, so
it is not injectable.
"""
from __future__ import annotations

from benchmarks.datasets._common import classify_verb
from benchmarks.live.planner import verb_class_order
from clayseal.capabilities.monitor import IntentEnvelope, Phase

__all__ = ["classify_verb", "envelope_for_tools", "verb_class_order"]


def envelope_for_tools(tools: tuple[str, ...]) -> IntentEnvelope:
    """Build a sealed envelope over exactly these tools.

    Phases are per-tool with `min=0`: presence is what the membership check
    cares about, and requiring each phase to fire would make an agent that
    skips a tool look like a deviation.
    """
    phases = tuple(Phase(tools=frozenset({name}), min=0) for name in tools)
    verbs = frozenset(classify_verb(name) for name in tools)
    return IntentEnvelope(
        allowed_tools=frozenset(tools),
        allowed_verbs=verbs,
        # The demo's tools all address one resource class (`mcp:tool:<name>`),
        # so resource-class membership adds nothing here and is left open.
        # Tool membership above is the constraint that carries the signal.
        allowed_resource_classes=frozenset(),
        phases=phases,
        phase_order=verb_class_order(phases),
    )
