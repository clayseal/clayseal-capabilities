"""Envelope generation (Phase C1): plan, ground, sign.

The control plane compiles a sealed goal into a signed Intent Envelope, once, on
trusted input. C1 is the smallest real version of the pipeline from
``docs/intent_envelope_generation.md``:

    plan  ->  verify (ground against the tool ontology)  ->  sign

``plan`` is produced by a :class:`Planner`. C1 ships the deterministic
``StructuredIntentPlanner`` (the plan is authored in the goal's
``structured_intent``); C2 will drop an LLM planner into the same seam. Whatever
the planner, it sees ONLY the sealed goal, never untrusted content, the CaMeL
privilege split and the Ulysses pre-commitment. ``verify`` rejects an incoherent
plan (a goal the tools cannot reach) so a hallucinated plan never gets sealed;
this is the neuro-symbolic discipline (the planner proposes, the ontology
disposes). Only a verified plan is signed.
"""
from __future__ import annotations

from dataclasses import dataclass
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
    derive_counts: bool = False,
    inferrer=None,
    infer_mode: str = "fill_gaps",
) -> CompiledEnvelope:
    """Plan, ground, and (if a signing key is given and the plan is coherent) seal.

    Passing ``key`` makes the envelope tamper-evident control-plane data. An
    unsatisfiable plan is never signed: the caller should reject the task, ask
    the user to clarify, or fall back to floor-only enforcement.
    """
    planner = planner or StructuredIntentPlanner(ontology=ontology)
    envelope = planner.plan(goal)
    if derive_counts:
        # OFF BY DEFAULT, and the reason is a measurement rather than a doubt
        # about the idea.
        #
        # The plan says which tools and whether a phase repeats, never how many
        # times, so a goal reading "email a summary" admitted one send and fifty
        # identically. Deriving the count here rather than asking an operator is
        # the point: 0 of 520 tasks across eleven corpora declare a budget, so a
        # rung that waits for a declaration is inert where it is needed most.
        #
        # What the derivation gets wrong is the number. "Email a summary" reads
        # as one send and a benign trajectory legitimately sends two, so the
        # bound is tight where the sentence was merely brief. Measured on
        # AgentHarm per SESSION: enabling it moves containment 45.0% to 46.2%
        # and false positives **0.0% to 10.2%**, and every one of those 46
        # refusals is this rung. Roughly eight points of false positive per
        # point of containment is not a trade, and a default nobody chose is
        # the wrong place to make it.
        #
        # Still here, still tested, still a step-up rather than a denial, and
        # `compile_envelope(goal, derive_counts=True)` turns it on for a
        # deployment that has measured the exchange on its own traffic.
        #
        # Sealed-goal text only, and this runs at seal time before any untrusted
        # content exists, so the number cannot be influenced by what the agent
        # later reads. Exceeding it is a STEP_UP and never a denial: a derived
        # bound is evidence that the trace left the plan, not proof the action is
        # wrong.
        from agentauth.capabilities.monitor.multiplicity import apply_multiplicity

        # `inferrer` is OPTIONAL and off unless a caller passes one. The
        # deterministic reading is the default because it is reproducible and a
        # reviewer can check it against the sentence; a model's proposal is
        # neither, so it fills gaps rather than overruling evidence, and under
        # `fill_gaps` it can only create a bound where none existed. Both modes
        # forbid raising a bound the text supports.
        envelope = apply_multiplicity(
            envelope, goal.summary or "", inferrer=inferrer, mode=infer_mode)
    satisfiable, issues = verify_plan(envelope)
    signed = sign_intent_envelope(envelope, key=key) if (key is not None and satisfiable) else None
    return CompiledEnvelope(
        envelope=envelope, satisfiable=satisfiable, issues=tuple(issues), signed=signed,
    )
