"""Default provenance-typed slots for egress / effect tools.

AuthGraph's precision comes from parameter-source policies: a ``send_email``
``to`` may be filled from a trusted read or the sealed goal, not from free
invention. The live planner currently emits tool membership only. These
templates close that gap without an LLM: every effect tool that takes a
destination-shaped argument gets a ``trusted_read`` (or ``goal``) slot.

Enforcement is via ``IntentEnvelope.check_slots``, OFF_SLOT × consequential
denies. Structured grounding yields ``DestinationTrust.ALLOW``; free-text of a
goal-named object steps up at the egress floor and fails a TRUSTED_READ slot,
which is the measured correct response to co-located injection.
"""
from __future__ import annotations

from clayseal.capabilities.monitor.intent_envelope import (
    CallTemplate,
    ParameterSlot,
    SlotSource,
)

# tool-name substrings → destination argument names that must be grounded.
_EGRESS_SLOT_NAMES: tuple[str, ...] = (
    "to", "recipient", "recipients", "email", "account", "address",
    "url", "destination", "dest", "webhook", "host",
)

_EFFECT_HINTS: tuple[str, ...] = (
    "send", "email", "mail", "transfer", "pay", "wire", "post", "share",
    "upload", "http", "request", "webhook", "notify", "message", "slack",
)


def _is_effect_tool(name: str) -> bool:
    n = name.lower()
    return any(h in n for h in _EFFECT_HINTS)


def egress_templates_for_tools(
    tools: list[str] | set[str] | frozenset[str],
    *,
    source: SlotSource = SlotSource.TRUSTED_READ,
) -> tuple[CallTemplate, ...]:
    """One CallTemplate per effect-like tool with TRUSTED_READ destination slots."""
    out: list[CallTemplate] = []
    for tool in sorted(tools):
        if not _is_effect_tool(tool):
            continue
        slots = tuple(
            ParameterSlot(name=n, source=source) for n in _EGRESS_SLOT_NAMES
        )
        # Verb class left open: live tools use send/transfer/post/call variously.
        out.append(CallTemplate(tool=tool, verb_class="", slots=slots))
    return tuple(out)
