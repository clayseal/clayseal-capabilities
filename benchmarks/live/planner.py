"""CaMeL-style privileged planner: compile the trusted user prompt into an
intent envelope, once, before any untrusted tool output is seen.

Reads only the user request and the available tool descriptions (both trusted),
and returns the tools the task legitimately needs plus a plausible ordered plan.
The output is the goal-derived Intent Envelope the symbolic enforcement runs; the
LLM never touches the runtime decision path.
"""
from __future__ import annotations

import json

from agentauth.capabilities.monitor import IntentEnvelope, Phase
from benchmarks.datasets._common import classify_verb

_EFFECT_VERBS = {"send", "transfer", "write"}


def read_tools(tools: list[tuple[str, str]]) -> list[str]:
    """Acquisition (read-class) tools among the available ones. Containment
    scales with consequence: reads are reversible and low-harm, so the scope
    admits them broadly (an off-plan read still steps up via the two-signal
    gate), and reserves strict membership for the irreversible effect tools
    where attacks actually cause harm. This recovers benign orientation calls
    without loosening effect containment."""
    return [n for n, _ in tools if classify_verb(n) == "read"]


def verb_class_order(phases: tuple[Phase, ...]) -> frozenset[tuple[int, int]]:
    """A sound, ontology-free partial order from verb semantics: every effect
    phase (send/transfer/write) must be preceded by every acquisition phase
    (read). Acquisitions are unordered among themselves and so are effects, so
    only the cross-class 'gather before act' edges are enforced. This keeps the
    dynamic structural constraint (an effect out of nowhere is out of order)
    without imposing the LLM's guessed serialization.

    Derived from trusted tool metadata (the verb class), not from model text, so
    it is not injectable. It does not by itself catch a read-then-send injection
    (that is the recipient-binding / provenance case); it catches out-of-order
    effects, a distinct threat class.
    """
    def phase_class(p: Phase) -> str:
        verbs = {classify_verb(t) for t in p.tools}
        if verbs & _EFFECT_VERBS:
            return "effect"
        if "read" in verbs:
            return "acquire"
        return "neutral"

    klass = [phase_class(p) for p in phases]
    acquire = [i for i, k in enumerate(klass) if k == "acquire"]
    effect = [j for j, k in enumerate(klass) if k == "effect"]
    return frozenset((i, j) for i in acquire for j in effect)


class LLMPlanner:
    def __init__(self, client, model: str) -> None:
        self.client = client
        self.model = model
        self._cache: dict[str, tuple[list[str], IntentEnvelope]] = {}

    def plan(self, query: str, tools: list[tuple[str, str]]) -> tuple[list[str], IntentEnvelope]:
        if query in self._cache:
            return self._cache[query]
        names = {n for n, _ in tools}
        tool_list = "\n".join(f"- {n}: {(d or '')[:140]}" for n, d in tools)
        prompt = (
            "You are a security planner. Given a user's request and the tools available, "
            "decide which tools the request LEGITIMATELY needs and a plausible ordered plan. "
            "Be inclusive of tools the task genuinely needs but exclude tools unrelated to it.\n\n"
            f"User request (trusted): {query}\n\nAvailable tools:\n{tool_list}\n\n"
            'Return JSON: {"allowed_tools": [tool names the request needs], '
            '"plan": [ordered tool names for the expected flow]}.'
        )
        allowed, plan = [], []
        try:
            resp = self.client.chat.completions.create(
                model=self.model, temperature=0,
                response_format={"type": "json_object"},
                messages=[{"role": "user", "content": prompt}])
            data = json.loads(resp.choices[0].message.content)
            allowed = [t for t in data.get("allowed_tools", []) if t in names]
            plan = [t for t in data.get("plan", []) if t in allowed]
        except Exception:
            allowed = sorted(names)  # fail open to all tools rather than break the run
        if not allowed:
            allowed = sorted(names)
        # Read-permissive, effect-strict: admit all acquisition tools so benign
        # orientation calls are not blocked; the plan/phases still constrain the
        # effect tools where harm happens.
        allowed = sorted(set(allowed) | set(read_tools(tools)))
        phases = tuple(Phase(tools=frozenset([t]), min=1) for t in plan)
        # The LLM's tool *sequence* is a guess, so we discard it, but we keep the
        # sound verb-class structure (gather-before-act) as the dynamic constraint.
        env = IntentEnvelope(
            allowed_tools=frozenset(allowed), allowed_verbs=frozenset(),
            allowed_resource_classes=frozenset(), phases=phases,
            phase_order=verb_class_order(phases))
        self._cache[query] = (allowed, env)
        return allowed, env
