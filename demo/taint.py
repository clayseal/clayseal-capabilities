"""Linking an action to the untrusted content that could have caused it.

THE DESIGN DECISION THAT MAKES THIS WORK: taint links DESTINATIONS, not
payloads.

In a summarization task the payload is derived from tool output *by design*
that is the whole job. If `derived_from` were computed over the full argument
blob, every legitimate summary email would come out "tainted x consequential"
and the ladder would fire on correct behaviour, which is the classic way a
provenance defense destroys its own utility.

What actually separates the attack is narrower and checkable: the DESTINATION
came from content the agent read, and appears nowhere in the sealed goal. The
summary's recipient was named by the user; the collector's address exists only
inside a ticket. That is the signal, and it is the same structured-vs-free-text
reasoning `benchmarks/live/broker_defense.py::observe_output` arrived at from the
opposite direction (which destinations may be *trusted*).

Consequence: a run where the model dutifully pastes harvested data into a
legitimately-addressed email is NOT caught here, the broker's argument scan
catches that instead (`extract_destinations` reads every string argument). Two
mechanisms, two threat shapes; neither is asked to do the other's job.
"""
from __future__ import annotations

from agentauth.capabilities.hardening.egress_policy import (
    extract_destinations,
    extract_recipients,
)
from agentauth.capabilities.monitor.action import ContextItem, TrustLevel


def _norm(text: str) -> str:
    return "".join(str(text).lower().split())


def destinations_in_args(args: dict) -> set[str]:
    """Every destination-shaped value in a call's arguments."""
    return set(extract_destinations("", args)) | set(extract_recipients(args))


def derive_sources(args: dict, returns: list[tuple[ContextItem, str]],
                   sealed_text: str) -> tuple[str, ...]:
    """Ids of the untrusted returns that could have supplied this destination.

    A destination named in the sealed goal is excluded: the user asked for it,
    so it is not something the agent learned from a document.
    """
    dests = destinations_in_args(args)
    sealed = _norm(sealed_text)
    novel = {d for d in dests if _norm(d) not in sealed}
    if not novel:
        return ()
    return tuple(item.item_id for item, text in returns
                 if any(_norm(d) in _norm(text) for d in novel))


def untrusted_return(step: int, tool: str) -> ContextItem:
    """Register a tool return as untrusted context.

    Untrusted by PROVENANCE, not by inspection. `context_item_from_content`
    defaults to TRUSTED and only downgrades when input-hardening finds delivery
    markers (zero-width, bidi, homoglyphs), a clean ASCII instruction in a
    ticket would sail through it. The honest rule is simpler: it came out of a
    tool, so the agent did not author it and the user did not sanction it.
    """
    return ContextItem(item_id=f"ret:{step}", trust=TrustLevel.UNTRUSTED,
                       introduced_at_step=step, summary=f"{tool} return")
