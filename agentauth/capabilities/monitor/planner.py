"""The privileged planner: compile a trusted request into a sealed envelope.

The intent envelope is the primary behavioural tier, the thing that decides
whether an action the floor allowed is a step the task actually implies. Nothing
in the shipped package could build one from a real user request. ``generation.py``
ships ``StructuredIntentPlanner``, which reads a plan the goal ALREADY contains,
and the planner that produces one from a prompt lived in ``benchmarks/live/
planner.py``, outside the wheel, in the harness.

Every live AgentDojo number in ``benchmarks/results/`` was produced by that
benchmark file. A deployment installing the package got either a hand-authored
``structured_intent`` or no envelope at all, and no envelope is a materially
different security posture from the one that was measured. That gap is what this
module closes.

THE TRUST ARGUMENT
------------------
The planner runs ONCE, on the trusted user request and the trusted tool
descriptions, BEFORE any tool output exists. It is the CaMeL privilege split and
the Ulysses pre-commitment: the model that could be injected never touches the
enforcement decision, because by the time injectable content arrives the plan is
already sealed. The model is in the CONTROL plane, not the decision path.

Two properties follow, and both are enforced here rather than assumed:

- ``plan()`` takes a query and a tool catalog and nothing else. There is no
  parameter through which tool output could reach it.
- The LLM's tool SEQUENCE is discarded. It is a guess, and enforcing a guessed
  serialisation blocks benign work. What survives is the sound structural
  constraint, every acquisition phase precedes every effect phase, derived
  from verb semantics rather than from model text, and so not injectable.

FAILING WITHOUT FAILING OPEN
----------------------------
A planner outage previously admitted every tool in the catalog, with the comment
"fail open to all tools rather than break the run". That is an undefended run
reported as a defended one, and ``benchmarks/results/denial_diagnosis.md``
records the same defect class costing a 50-point phantom improvement.

The degraded path admits the ACQUISITION tools only. The agent can still orient,
every consequential action falls outside the empty plan and steps up rather than
executing, and ``degraded`` is set on the envelope so a run built this way can be
excluded from a defended measurement rather than silently counted as one.
"""
from __future__ import annotations

import json
import time
from typing import Any, Protocol, runtime_checkable

from agentauth.capabilities.monitor.egress_slots import egress_templates_for_tools
from agentauth.capabilities.monitor.intent_envelope import IntentEnvelope, Phase

#: Verb prefixes, in the classifier's precedence order. A leading acquisition
#: verb wins over a later write-like substring: `get_scheduled_transactions` is a
#: read even though it contains `schedule`. Misreading a read as an effect makes
#: the floor hard-deny a benign, reversible call, which is the main utility leak.
_WRITE_VERBS = (
    "create", "update", "delete", "send", "pay", "transfer", "set", "add",
    "remove", "cancel", "book", "post", "share", "write", "schedule",
    "execute", "run", "make", "submit", "toggle", "enable", "disable",
    "refund", "exchange", "modify", "reserve", "mkdir", "mv", "cp", "rm",
    "touch", "echo",
)
_READ_VERBS = (
    "get", "list", "search", "read", "find", "view", "show", "check",
    "fetch", "lookup", "query", "describe", "calculate", "cd", "ls", "cat",
    "grep", "sort", "diff", "pwd", "du", "wc", "tail", "head",
)
#: Classes that move something irreversible, used to order phases.
_EFFECT_CLASSES = frozenset({"send", "transfer", "write"})

PLANNER_PROMPT = (
    "You are a security planner. Given a user's request and the tools available, "
    "decide which tools the request LEGITIMATELY needs and a plausible ordered "
    "plan. Be inclusive of tools the task genuinely needs but exclude tools "
    "unrelated to it.\n\n"
    "User request (trusted): {query}\n\nAvailable tools:\n{tools}\n\n"
    'Return JSON: {{"allowed_tools": [tool names the request needs], '
    '"plan": [ordered tool names for the expected flow]}}.'
)


def classify_verb(tool: str) -> str:
    """The verb class of a tool NAME. Trusted metadata, never model text."""
    low = tool.lower()
    for verb in _READ_VERBS:
        if low.startswith(verb):
            return "read"
    for verb in _WRITE_VERBS:
        if low.startswith(verb) or f"_{verb}" in low:
            if verb in ("pay", "transfer", "refund", "exchange"):
                return "transfer"
            if verb == "send":
                return "send"
            return "write"
    for verb in _READ_VERBS:
        if f"_{verb}" in low:
            return "read"
    return "call"


def read_tools(tools: list[tuple[str, str]]) -> list[str]:
    """The acquisition tools in a catalog.

    Containment scales with consequence: reads are reversible and low-harm, so
    the plan admits them broadly (an off-plan read still steps up via the
    two-signal gate) and reserves strict membership for the irreversible effect
    tools, where attacks actually cause harm. This recovers benign orientation
    calls without loosening effect containment.
    """
    return [name for name, _ in tools if classify_verb(name) == "read"]


def verb_class_order(phases: tuple[Phase, ...]) -> frozenset[tuple[int, int]]:
    """A sound, ontology-free partial order: gather before you act.

    Every effect phase must be preceded by every acquisition phase. Acquisitions
    are unordered among themselves and so are effects, so only the cross-class
    edges are enforced, the dynamic structural constraint without the LLM's
    guessed serialisation.

    This does not by itself catch a read-then-send injection; that is the
    destination-binding and provenance case. It catches an effect out of
    nowhere, which is a distinct threat class.
    """
    def phase_class(phase: Phase) -> str:
        classes = {classify_verb(t) for t in phase.tools}
        if classes & _EFFECT_CLASSES:
            return "effect"
        if "read" in classes:
            return "acquire"
        return "neutral"

    kinds = [phase_class(p) for p in phases]
    acquire = [i for i, k in enumerate(kinds) if k == "acquire"]
    effect = [j for j, k in enumerate(kinds) if k == "effect"]
    return frozenset((i, j) for i in acquire for j in effect)


def envelope_from_plan(
    allowed: list[str],
    plan: list[str],
    tools: list[tuple[str, str]],
    *,
    degraded: bool = False,
    planner_error: str = "",
) -> IntentEnvelope:
    """Assemble a sealed envelope from a tool set and an ordered plan.

    Split out from the LLM path so a deterministic planner, a hand-authored plan
    or a test fixture produces an envelope through exactly the same construction
    the measured live runs used.
    """
    admitted = sorted(set(allowed) | set(read_tools(tools)))
    phases = tuple(Phase(tools=frozenset([t]), min=1) for t in plan)
    envelope = IntentEnvelope(
        allowed_tools=frozenset(admitted),
        allowed_verbs=frozenset(),
        allowed_resource_classes=frozenset(),
        phases=phases,
        phase_order=verb_class_order(phases),
        # Provenance-typed destination slots: a send/transfer/post `to` must come
        # from a trusted read or the sealed goal, not from free invention.
        call_templates=egress_templates_for_tools(admitted),
    )
    envelope.degraded = degraded
    envelope.planner_error = planner_error
    return envelope


@runtime_checkable
class QueryPlanner(Protocol):
    """Builds an envelope from a trusted request and a trusted tool catalog."""

    name: str

    def plan(
        self, query: str, tools: list[tuple[str, str]]
    ) -> tuple[list[str], IntentEnvelope]:
        ...


class LLMQueryPlanner:
    """Compile the trusted user prompt into an intent envelope, once.

    ``client`` is any object exposing the OpenAI-style
    ``chat.completions.create``; the package does not depend on a provider SDK.
    Results are cached on ``(query, tool set)``, keying on the query alone
    returns a plan built for a different catalog whenever the same request runs
    against a different tool set, which is exactly what an ablation sweep does.
    """

    name = "llm-query"

    def __init__(
        self,
        client: Any,
        model: str,
        *,
        attempts: int = 3,
        backoff_seconds: float = 0.4,
    ) -> None:
        self.client = client
        self.model = model
        self.attempts = max(1, attempts)
        self.backoff_seconds = backoff_seconds
        self._cache: dict[tuple, tuple[list[str], IntentEnvelope]] = {}

    def plan(
        self, query: str, tools: list[tuple[str, str]]
    ) -> tuple[list[str], IntentEnvelope]:
        key = (query, tuple(sorted(name for name, _ in tools)))
        if key in self._cache:
            return self._cache[key]

        names = {name for name, _ in tools}
        catalog = "\n".join(f"- {n}: {(d or '')[:140]}" for n, d in tools)
        prompt = PLANNER_PROMPT.format(query=query, tools=catalog)

        allowed: list[str] = []
        plan: list[str] = []
        degraded = False
        last_error: Exception | None = None

        for attempt in range(self.attempts):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    temperature=0,
                    response_format={"type": "json_object"},
                    messages=[{"role": "user", "content": prompt}],
                )
                data = json.loads(response.choices[0].message.content)
                # ValueError, not TypeError, and deliberately: a malformed shape
                # from the model is bad DATA on a retryable path, not a caller
                # passing the wrong type. The retry loop below treats every
                # exception the same way, so this only affects what a reader
                # sees in `planner_error`.
                if not isinstance(data, dict):
                    raise ValueError(  # noqa: TRY004
                        f"planner returned {type(data).__name__}")
                raw_allowed = data.get("allowed_tools") or []
                raw_plan = data.get("plan") or []
                if not isinstance(raw_allowed, list) or not isinstance(raw_plan, list):
                    raise ValueError(  # noqa: TRY004
                        "allowed_tools/plan must be lists")
                # Intersect with the real catalog: a hallucinated tool name must
                # not become an authorization.
                allowed = [t for t in raw_allowed if t in names]
                plan = [t for t in raw_plan if t in allowed]
                break
            except Exception as exc:  # noqa: BLE001 - retried, then degraded
                last_error = exc
                if attempt < self.attempts - 1:
                    time.sleep(self.backoff_seconds * (attempt + 1))

        if not allowed:
            # DEGRADED, not fail-open. Three paths reach here and all three used
            # to admit the entire catalog: a raised exception, a well-formed
            # answer with an empty `allowed_tools`, and a malformed shape.
            allowed = sorted(read_tools(tools))
            plan = []
            degraded = True

        envelope = envelope_from_plan(
            allowed, plan, tools,
            degraded=degraded,
            planner_error=repr(last_error)[:200] if degraded and last_error else "",
        )
        result = (sorted(envelope.allowed_tools), envelope)
        self._cache[key] = result
        return result
