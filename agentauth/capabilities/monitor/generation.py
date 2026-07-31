"""Envelope generation (Phase C1): plan, ground, sign.

The control plane compiles a sealed goal into a signed Intent Envelope, once, on
trusted input. C1 is the smallest real version of the pipeline from
``docs/intent_envelope_generation.md``:

    plan  ->  verify (ground against the tool ontology)  ->  sign

``plan`` is produced by a :class:`Planner`. C1 ships the deterministic
``StructuredIntentPlanner`` (the plan is authored in the goal's
``structured_intent``); C2 will drop an LLM planner into the same seam. Whatever
the planner, it sees ONLY the sealed goal, never untrusted content — the CaMeL
privilege split and the Ulysses pre-commitment. ``verify`` rejects an incoherent
plan (a goal the tools cannot reach) so a hallucinated plan never gets sealed;
this is the neuro-symbolic discipline (the planner proposes, the ontology
disposes). Only a verified plan is signed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from agentauth.capabilities.monitor.intent_envelope import (
    IntentEnvelope,
    sign_intent_envelope,
)
from agentauth.capabilities.monitor.ontology import ToolOntology
from agentauth.capabilities.scoping.goal import GoalSpec


@runtime_checkable
class Planner(Protocol):
    name: str

    def plan(self, goal: GoalSpec) -> IntentEnvelope:
        """Produce a plan from the sealed goal ALONE (no untrusted content)."""
        ...


class StructuredIntentPlanner:
    """C1 planner: the plan is authored in the goal's ``structured_intent``.

    Deterministic and injection-trivially-safe (it reads only the goal). It is
    the honest floor for generation and the seam an LLM planner replaces in C2.
    """

    name = "structured-intent"

    def __init__(self, ontology: ToolOntology | None = None) -> None:
        self._ontology = ontology

    def plan(self, goal: GoalSpec) -> IntentEnvelope:
        return IntentEnvelope.from_goal(goal, ontology=self._ontology)


def verify_plan(envelope: IntentEnvelope) -> tuple[bool, list[str]]:
    """Ground a generated plan. Returns ``(ok, issues)``.

    ``ok`` is False only for a *fatal* incoherence (the goal is unreachable with
    the available tools). Non-fatal issues (dangling references, an empty plan)
    are reported but do not block sealing.
    """
    issues: list[str] = []

    satisfiable, why = envelope.is_satisfiable()
    if not satisfiable:
        issues.append(f"unsatisfiable plan: {why}")

    if not envelope.allowed_tools and not envelope.phases:
        issues.append("empty plan: no tools or phases declared for the goal")

    # Phases must reference tools the plan admits.
    for i, phase in enumerate(envelope.phases):
        dangling = phase.tools - envelope.allowed_tools
        if dangling:
            issues.append(f"phase {i} references tools not in the plan: {sorted(dangling)}")

    # Ontology preconditions should be establishable by some tool or be initial.
    if envelope.ontology is not None:
        producible = set(envelope.initial_facts)
        for spec in envelope.ontology.specs.values():
            producible |= spec.establishes
        for spec in envelope.ontology.specs.values():
            unmeetable = spec.preconditions - producible
            if unmeetable:
                issues.append(
                    f"tool {spec.tool!r} needs facts nothing establishes: {sorted(unmeetable)}")

    return satisfiable, issues


@dataclass
class CompiledEnvelope:
    """The output of the seal-time pipeline."""

    envelope: IntentEnvelope
    satisfiable: bool
    issues: tuple[str, ...] = ()
    signed: dict | None = None

    @property
    def sealed(self) -> bool:
        return self.signed is not None


def compile_envelope(
    goal: GoalSpec,
    *,
    planner: Planner | None = None,
    ontology: ToolOntology | None = None,
    key=None,
) -> CompiledEnvelope:
    """Plan, ground, and (if a signing key is given and the plan is coherent) seal.

    Passing ``key`` makes the envelope tamper-evident control-plane data. An
    unsatisfiable plan is never signed: the caller should reject the task, ask
    the user to clarify, or fall back to floor-only enforcement.
    """
    planner = planner or StructuredIntentPlanner(ontology=ontology)
    envelope = planner.plan(goal)
    satisfiable, issues = verify_plan(envelope)
    signed = sign_intent_envelope(envelope, key=key) if (key is not None and satisfiable) else None
    return CompiledEnvelope(
        envelope=envelope, satisfiable=satisfiable, issues=tuple(issues), signed=signed,
    )
