"""Behavior-tree plan representation (Phase C3).

A behavior tree is the natural home for a multi-modal plan: SELECTOR nodes are
the alternative modes (plausible different plans), SEQUENCE nodes are ordered
phases within a mode, LOOP nodes are repeatable phases, and LEAF nodes are typed
action classes. Behavior trees are the standard structure for a bounded space of
plausible behaviors in robotics and games.

Conformance reuses the phase machinery by *linearizing* the tree into its set of
mode paths: a SELECTOR expands into alternatives, a SEQUENCE concatenates, a LOOP
becomes a repeatable phase, a LEAF is one phase. The trace conforms if it is
consistent with at least one mode (the MultiPath "track any plausible anchor"
idea). Bounded trees give a bounded set of modes.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace
from enum import Enum

from agentauth.capabilities.monitor.intent_envelope import (
    Deviation,
    IntentConformance,
    IntentEnvelope,
    Phase,
    StepConformance,
    _parse_phases,
)
from agentauth.capabilities.monitor.ontology import ToolOntology


class NodeKind(str, Enum):
    LEAF = "leaf"
    SEQUENCE = "sequence"   # ordered children (AND)
    SELECTOR = "selector"   # alternative children (OR / modes)
    LOOP = "loop"           # a repeatable child


@dataclass(frozen=True)
class PlanNode:
    kind: NodeKind
    phase: Phase | None = None
    children: tuple[PlanNode, ...] = ()
    loop_min: int = 0


# -- builders ---------------------------------------------------------------
def leaf(*, tools=(), verbs=(), resource_classes=(), min: int = 0, repeatable: bool = True) -> PlanNode:
    return PlanNode(NodeKind.LEAF, phase=Phase(
        tools=frozenset(tools), verbs=frozenset(v.lower() for v in verbs),
        resource_classes=frozenset(resource_classes), min=min, repeatable=repeatable))


def sequence(*children: PlanNode) -> PlanNode:
    return PlanNode(NodeKind.SEQUENCE, children=tuple(children))


def selector(*children: PlanNode) -> PlanNode:
    return PlanNode(NodeKind.SELECTOR, children=tuple(children))


def loop(child: PlanNode, *, min: int = 0) -> PlanNode:
    return PlanNode(NodeKind.LOOP, children=(child,), loop_min=min)


# -- linearization ----------------------------------------------------------
def linearize(node: PlanNode, *, cap: int = 128) -> list[tuple[Phase, ...]]:
    """Expand the tree into its set of mode paths (each a phase sequence)."""
    if node.kind is NodeKind.LEAF:
        return [(node.phase,)] if node.phase is not None else [()]
    if node.kind is NodeKind.LOOP:
        child = node.children[0]
        return [tuple(replace(p, repeatable=True, min=max(p.min, node.loop_min)) for p in lin)
                for lin in linearize(child, cap=cap)]
    if node.kind is NodeKind.SEQUENCE:
        result: list[tuple[Phase, ...]] = [()]
        for child in node.children:
            child_lins = linearize(child, cap=cap)
            result = [r + cl for r in result for cl in child_lins][:cap]
        return result
    if node.kind is NodeKind.SELECTOR:
        out: list[tuple[Phase, ...]] = []
        for child in node.children:
            out.extend(linearize(child, cap=cap))
        return out[:cap]
    return [()]


def envelope_from_tree(
    tree: PlanNode,
    *,
    goal_conditions=(),
    initial_facts=(),
    ontology: ToolOntology | None = None,
    extra_tools=(),
    verbs=(),
    resource_classes=(),
) -> IntentEnvelope:
    """Compile a behavior tree into a multi-mode Intent Envelope.

    The tree itself is stored (``plan_tree``) and conformance runs over it via an
    NFA, no linearization, so nested selectors do not explode. ``modes`` is kept
    for inspection/serialization fallback but the tree is authoritative.
    """
    modes = tuple(linearize(tree))
    tools: set[str] = set(extra_tools)
    vset: set[str] = {v.lower() for v in verbs}
    rset: set[str] = set(resource_classes)
    for mode in modes:
        for phase in mode:
            tools |= set(phase.tools)
            vset |= set(phase.verbs)
            rset |= set(phase.resource_classes)
    return IntentEnvelope(
        allowed_tools=frozenset(tools),
        allowed_verbs=frozenset(vset),
        allowed_resource_classes=frozenset(rset),
        phases=modes[0] if modes else (),
        modes=modes,
        plan_tree=tree,
        goal_conditions=frozenset(goal_conditions),
        initial_facts=frozenset(initial_facts),
        ontology=ontology,
    )


# --------------------------------------------------------------------------- #
# Serialization
# --------------------------------------------------------------------------- #
def node_to_dict(node: PlanNode) -> dict:
    d: dict = {"kind": node.kind.value}
    if node.phase is not None:
        d["phase"] = node.phase.to_dict()
    if node.children:
        d["children"] = [node_to_dict(c) for c in node.children]
    if node.loop_min:
        d["loop_min"] = node.loop_min
    return d


def node_from_dict(raw: dict) -> PlanNode:
    kind = NodeKind(raw["kind"])
    phase = _parse_phases([raw["phase"]])[0] if raw.get("phase") else None
    children = tuple(node_from_dict(c) for c in raw.get("children", []))
    return PlanNode(kind=kind, phase=phase, children=children, loop_min=int(raw.get("loop_min", 0)))


# --------------------------------------------------------------------------- #
# NFA conformance (Thompson construction + online subset simulation)
# --------------------------------------------------------------------------- #
class _NFA:
    def __init__(self) -> None:
        self.n = 0
        self.eps: dict[int, set[int]] = defaultdict(set)
        self.trans: dict[int, list[tuple[Phase, int]]] = defaultdict(list)
        self.start = 0
        self.accept = 0

    def state(self) -> int:
        s = self.n
        self.n += 1
        return s


def _build(nfa: _NFA, node: PlanNode) -> tuple[int, int]:
    if node.kind is NodeKind.LEAF:
        s = nfa.state()
        phase = node.phase
        reps = max(phase.min, 0) if phase else 0
        cur = s
        for _ in range(reps):
            nxt = nfa.state()
            nfa.trans[cur].append((phase, nxt))
            cur = nxt
        acc = cur
        if phase is not None and phase.repeatable:
            nfa.trans[acc].append((phase, acc))  # one-or-more
        if reps == 0:
            acc = s  # optional: start is already accepting
        return s, acc
    if node.kind is NodeKind.SEQUENCE:
        start = nfa.state()
        cur = start
        for child in node.children:
            cs, ca = _build(nfa, child)
            nfa.eps[cur].add(cs)
            cur = ca
        return start, cur
    if node.kind is NodeKind.SELECTOR:
        start, acc = nfa.state(), nfa.state()
        for child in node.children:
            cs, ca = _build(nfa, child)
            nfa.eps[start].add(cs)
            nfa.eps[ca].add(acc)
        return start, acc
    if node.kind is NodeKind.LOOP:
        start = nfa.state()
        cur = start
        for _ in range(max(node.loop_min, 0)):
            cs, ca = _build(nfa, node.children[0])
            nfa.eps[cur].add(cs)
            cur = ca
        acc = cur
        cs, ca = _build(nfa, node.children[0])
        nfa.eps[acc].add(cs)
        nfa.eps[ca].add(acc)
        if node.loop_min == 0:
            nfa.eps[start].add(acc)
        return start, acc
    s = nfa.state()
    return s, s


def _compile(tree: PlanNode) -> _NFA:
    nfa = _NFA()
    start, acc = _build(nfa, tree)
    nfa.start, nfa.accept = start, acc
    return nfa


def _closure(states: set[int], eps: dict[int, set[int]]) -> set[int]:
    stack, seen = list(states), set(states)
    while stack:
        for t in eps[stack.pop()]:
            if t not in seen:
                seen.add(t)
                stack.append(t)
    return seen


def tree_conformance(envelope: IntentEnvelope, traj) -> IntentConformance:
    """Per-step conformance of a trace against the envelope's behavior tree.

    Membership first (a foreign tool is off-tool). Then subset-simulate the NFA:
    an action that some active state can consume advances the set (in-plan); an
    action that no active state can consume but that IS a plan step elsewhere is
    out-of-order for this point in the plan; an auxiliary tool is permitted and
    leaves the state unchanged.
    """
    nfa = _compile(envelope.plan_tree)  # type: ignore[arg-type]
    active = _closure({nfa.start}, nfa.eps)
    plan_tools = envelope._plan_tools()
    steps: list[StepConformance] = []
    for action in traj.actions:
        off = envelope._membership(action)
        if off is not None:
            steps.append(off)
            continue
        nxt: set[int] = set()
        for s in active:
            for phase, target in nfa.trans[s]:
                if phase.matches(action):
                    nxt.add(target)
        if nxt:
            active = _closure(nxt, nfa.eps)
            steps.append(StepConformance(action.step, Deviation.IN_PLAN, "in plan"))
        elif action.tool in plan_tools:
            steps.append(StepConformance(
                action.step, Deviation.OUT_OF_ORDER,
                f"{action.tool!r} not valid at this point in the plan"))
        else:
            steps.append(StepConformance(action.step, Deviation.IN_PLAN, "in plan"))
    return IntentConformance(steps=steps)
