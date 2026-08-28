"""Symbolic diverse-planner (Phase C2), derive the envelope from the ontology.

Instead of asking an LLM for a plan (a soft, stochastic, injectable function),
compute the plan structure directly from the tool ontology by classical
**landmark analysis**: the facts that must be achieved in *any* valid plan, and
the tools that can achieve them, and the necessary order among them. This is
deterministic, sound, and not injectable: it is an algorithm over a formal
domain model, not a model reading text, and it handles multi-modality for free:
when a fact can be achieved several ways (deploy by canary *or* blue-green),
neither tool is individually required, so the plan permits either.

Landmarks (Hoffmann/Porteous/Zhu-Givan, simplified): back-chain from the goal
conditions through the *shared* preconditions of a fact's achievers. Order two
landmark facts by necessity (f must precede g if g is unreachable while f is
withheld). The ordered fact-landmarks become achiever-keyed required phases, so
conformance enforces "build before deploy" while allowing any valid deploy tool.
"""
from __future__ import annotations

from clayseal.capabilities.monitor.action import resource_class
from clayseal.capabilities.monitor.intent_envelope import IntentEnvelope, Phase
from clayseal.capabilities.monitor.ontology import ToolOntology, ToolSpec
from clayseal.capabilities.scoping.goal import GoalSpec


def _reachable(specs: dict[str, ToolSpec], world: set[str], *, blocked_facts: frozenset[str] = frozenset()) -> set[str]:
    reachable = set(world) - blocked_facts
    changed = True
    while changed:
        changed = False
        for spec in specs.values():
            if spec.preconditions <= reachable:
                for fact in spec.establishes:
                    if fact not in reachable and fact not in blocked_facts:
                        reachable.add(fact)
                        changed = True
    return reachable


def _achievers(specs: dict[str, ToolSpec], fact: str) -> list[str]:
    return [t for t, s in specs.items() if fact in s.establishes]


def fact_landmarks(specs, initial: set[str], goals: set[str]) -> set[str]:
    """Facts every valid plan must achieve: back-chain the shared preconditions
    of each landmark's achievers from the goal."""
    landmarks = set(goals)
    frontier = set(goals)
    while frontier:
        fact = frontier.pop()
        achievers = _achievers(specs, fact)
        if not achievers:
            continue  # initial or unachievable, no shared prerequisite to add
        shared = set.intersection(*(set(specs[t].preconditions) for t in achievers))
        for pre in shared - initial:
            if pre not in landmarks:
                landmarks.add(pre)
                frontier.add(pre)
    return landmarks


def landmark_order(specs, initial: set[str], landmarks: set[str]) -> set[tuple[str, str]]:
    """``(f, g)`` means f must precede g: g is unreachable while f is withheld."""
    order: set[tuple[str, str]] = set()
    for f in landmarks:
        reachable_without_f = _reachable(specs, initial, blocked_facts=frozenset({f}))
        for g in landmarks:
            if f != g and g not in reachable_without_f:
                order.add((f, g))
    return order


def _toposort(nodes: list[str], edges: set[tuple[str, str]]) -> list[str]:
    incoming = dict.fromkeys(nodes, 0)
    for a, b in edges:
        if a in incoming and b in incoming:
            incoming[b] += 1
    ready = [n for n in nodes if incoming[n] == 0]
    out: list[str] = []
    while ready:
        ready.sort()  # deterministic order among independents
        n = ready.pop(0)
        out.append(n)
        for a, b in edges:
            if a == n and b in incoming:
                incoming[b] -= 1
                if incoming[b] == 0:
                    ready.append(b)
    # Any remaining (cycle, shouldn't happen in a monotone relaxation) appended.
    out.extend(n for n in nodes if n not in out)
    return out


class SymbolicPlanner:
    """A ``Planner`` that derives the plan from the ontology by landmark analysis.

    Non-injectable and sound. Falls back to membership-only compilation when the
    goal carries no ontology / goal conditions (nothing to reason over).
    """

    name = "symbolic-landmark"

    def __init__(self, ontology: ToolOntology | None = None) -> None:
        self._ontology = ontology

    def plan(self, goal: GoalSpec) -> IntentEnvelope:
        intent = goal.structured_intent or {}
        ontology = self._ontology or (
            ToolOntology.from_dict(intent["ontology"])
            if isinstance(intent.get("ontology"), list) else None
        )
        goal_conditions = {str(g) for g in intent.get("goal_conditions", [])}
        initial = {str(f) for f in intent.get("initial_facts", [])}

        if ontology is None or not goal_conditions:
            # No domain model to plan over: membership-only envelope.
            return IntentEnvelope.from_goal(goal, ontology=ontology)

        specs = ontology.specs
        landmarks = fact_landmarks(specs, initial, goal_conditions)
        # Only landmark facts that something achieves become phases.
        achievable = [f for f in landmarks if _achievers(specs, f)]
        order = landmark_order(specs, initial, set(achievable))
        # A topological order gives phases a stable index; the *partial* order is
        # preserved as edges so conformance enforces only the real precedences
        # (build-before-deploy) and lets independent phases interleave freely.
        ordered = _toposort(achievable, order)
        idx = {fact: i for i, fact in enumerate(ordered)}
        phase_order = frozenset(
            (idx[f], idx[g]) for (f, g) in order if f in idx and g in idx)

        phases = tuple(
            Phase(tools=frozenset(_achievers(specs, fact)), min=1)
            for fact in ordered
        )

        tools = set(specs) | set(intent.get("tools") or [])
        for r in goal.allow_resources:
            if r.startswith("mcp:tool:"):
                tools.add(r.rsplit(":", 1)[-1])
        verbs = {str(v).lower() for v in (intent.get("verbs") or [])}
        rclasses = {resource_class(r) for r in goal.allow_resources}
        return IntentEnvelope(
            allowed_tools=frozenset(tools),
            allowed_verbs=frozenset(verbs),
            allowed_resource_classes=frozenset(rclasses),
            phases=phases,
            phase_order=phase_order,
            goal_conditions=frozenset(goal_conditions),
            initial_facts=frozenset(initial),
            ontology=ontology,
        )
