"""Enforce a compiled tool ontology: refuse an act whose prerequisites never ran.

WHAT THIS IS, AND WHY IT IS NOT A LEXICON
-----------------------------------------
The five goal-derived rungs read the operator's own sentence. That is their
strength and their ceiling: a goal in another vocabulary derives nothing, and
`benchmarks/results/containment_headroom.md` measures the wall precisely, the
goals name ROLES where the catalogue names ACTIONS.

This rung reads no sentence. It takes a `ToolOntology`, preconditions, effects
and reversibility per tool, compiled OFFLINE AND ONCE from the tool schemas
alone, and enforces it deterministically against what this session has actually
done. No natural language at decision time, no model, no network, no goal text.

WHY THE TWO HALVES WERE NEVER CONNECTED
---------------------------------------
The library has held `monitor/ontology.py` (the types) and
`monitor/symbolic_planner.py` (landmark analysis over them) for a long time. The
benchmark separately compiles ontologies for 131 of 132 catalogues into
`benchmarks/_ontology_cache.json` and enforces them with its OWN private ledger
in `benchmarks/precondition_rung.py`. Neither half ever met the other: the
landmark analysis has never run on a compiled ontology, and the compiled
ontology has never reached a `SessionBroker`.

This module is the missing half, promoted out of the harness so a deployment can
have it.

WHERE THE ONTOLOGY MAY COME FROM, AND WHY THAT IS SAFE
------------------------------------------------------
Any process that reads only the tool catalogue. A model compiling PDDL-style
operators from tool schemas is the route measured here, and it does not weaken
the provenance rule: it runs once per catalogue, before any session opens, so
nothing an attacker can influence is in scope at compile time, and decision time
is pure set membership against this session's own history.

THE SOUNDNESS MOVE
------------------
Only a fact that some tool in the catalogue ESTABLISHES is enforceable. A
precondition naming a fact nothing produces describes the world before the
session began, and the session cannot know whether it holds, so it is assumed to
hold. Without that rule the ledger refuses every tool whose compiled
preconditions mention any ambient state, which is most of them.

VALIDATION IS THE DEPLOYMENT'S JOB, AND IT IS NOT OPTIONAL
----------------------------------------------------------
A compiled precondition that legitimate traffic violates is not a precondition.
`refuted_by` drops those. On the benchmark this takes the arm from +9/-8 (a wash,
p=1.0) to +10/-0 (p=0.002), and every regression it removes is one error class,
preconditions the compiler attached to reads.

Read `validated_ontology.md` before quoting a completion number from that arm:
each catalogue there ships exactly one benign trace, so the traffic that refutes
the artifact is then the traffic scored, and the completion column is guaranteed
by construction rather than measured. Containment is honest, because validation
never sees an attack. A deployment does not have that problem, since it validates
against its own logs and serves different traffic afterwards.
"""
from __future__ import annotations

from typing import Any

from clayseal.capabilities.monitor.ontology import ToolOntology

__all__ = ["PreconditionLedger", "refuted_by"]


class PreconditionLedger:
    """Deterministic. Reads a compiled ontology and this session's history."""

    def __init__(self, ontology: ToolOntology | None = None, **kw: Any) -> None:
        self.ontology = ontology or ToolOntology()
        #: Facts some tool in this catalogue can establish. Anything outside this
        #: set is ambient world state the session cannot reason about.
        self.producible: set[str] = set()
        for spec in self.ontology.specs.values():
            self.producible |= set(spec.establishes)
        #: What this session has established, on the ALLOW path only.
        self.world: set[str] = set()

    def check(self, tool: str) -> tuple[bool, bool, str]:
        """(allowed, severe, reason). `severe` selects DENY over STEP_UP.

        An irreversible act with a missing prerequisite is the case worth a hard
        refusal: there is no later step that repairs it.
        """
        spec = self.ontology.spec(tool)
        if spec is None:
            return True, False, ""
        missing = sorted(
            f for f in spec.preconditions
            if f in self.producible and f not in self.world
        )
        if not missing:
            return True, False, ""
        return False, not spec.reversible, (
            f"{tool!r} requires {missing}, which nothing in this session has "
            f"established; the catalogue declares those facts producible"
        )

    def observe(self, tool: str) -> None:
        """Record an effect. Callers MUST call this on the allow path only.

        A refused call that still established its facts would discharge the
        obligation it was refused for, which is the defect the whole provenance
        discipline exists to prevent.
        """
        spec = self.ontology.spec(tool)
        if spec is None:
            return
        self.world |= set(spec.establishes)
        self.world -= set(spec.destroys)


def refuted_by(ontology: ToolOntology, traces: list[list[str]]) -> ToolOntology:
    """Drop every precondition that known-good traffic violates.

    `traces` are tool-name sequences a correct agent produced. Replaying one and
    finding a precondition unmet at the moment its tool ran is proof the
    precondition is wrong, because the trace is legitimate by assumption. This is
    the step that turns the compiled artifact from a wash into a result, and it
    needs no labels, no attacks and no human review.
    """
    bad: dict[str, set[str]] = {}
    for trace in traces:
        world: set[str] = set()
        producible: set[str] = set()
        for spec in ontology.specs.values():
            producible |= set(spec.establishes)
        for tool in trace:
            spec = ontology.spec(tool)
            if spec is None:
                continue
            for fact in spec.preconditions:
                if fact in producible and fact not in world:
                    bad.setdefault(spec.tool, set()).add(fact)
            world |= set(spec.establishes)
            world -= set(spec.destroys)

    if not bad:
        return ontology
    from dataclasses import replace

    kept = {}
    for name, spec in ontology.specs.items():
        drop = bad.get(name)
        kept[name] = (
            replace(spec, preconditions=frozenset(spec.preconditions - drop))
            if drop else spec
        )
    return ToolOntology(specs=kept)
