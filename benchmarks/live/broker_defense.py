"""Clay Seal broker as a live AgentDojo defense.

Replaces AgentDojo's ToolsExecutor with one that runs each proposed tool call
through a SessionBroker before executing it. A denied call is not executed; the
agent receives a "[BLOCKED by policy]" tool result and continues. This lets us
measure, on a live LLM agent under real injection attacks, the effect on attack
success rate and on task utility.

The broker is reset per run (detected by the first assistant turn) and the plan
is compiled once per user task from the *trusted* user prompt (never from tool
output), matching the CaMeL privileged-planner split.
"""
from __future__ import annotations

import re
from ast import literal_eval

from agentdojo.agent_pipeline.tool_execution import (
    EMPTY_FUNCTION_NAME,
    ChatToolResultMessage,
    ToolsExecutor,
    is_string_list,
    text_content_block_from_string,
    tool_result_to_str,
)

from agentauth.core.task_scope import TaskScope
from agentauth.capabilities.broker import Outcome, SessionBroker
from agentauth.capabilities.hardening.egress_policy import (
    EgressPolicy, extract_recipients)
from agentauth.capabilities.monitor import Action
from agentauth.capabilities.scoping.goal import GoalSpec
from benchmarks.datasets._common import classify_verb


def _all_text(obj, depth: int = 0, out=None) -> str:
    """Concatenate every string in a tool result, so destinations can be mined
    from free-text when the source resource is trusted (goal-named)."""
    if out is None:
        out = []
    if depth > 6 or obj is None:
        return " ".join(out)
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _all_text(v, depth + 1, out)
    elif isinstance(obj, (list, tuple, set)):
        for v in obj:
            _all_text(v, depth + 1, out)
    else:
        dump = getattr(obj, "model_dump", None)
        if callable(dump):
            try:
                _all_text(dump(), depth + 1, out)
            except Exception:
                pass
        else:
            d = getattr(obj, "__dict__", None)
            if isinstance(d, dict):
                _all_text(d, depth + 1, out)
    return " ".join(out)


def _iter_dicts(obj, depth: int = 0):
    """Yield every dict nested in a tool result (pydantic model, dataclass, list,
    dict), so structured fields can be mined for trusted destinations. Bounded
    depth keeps it cheap on large results."""
    if depth > 6 or obj is None:
        return
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _iter_dicts(v, depth + 1)
    elif isinstance(obj, (list, tuple, set)):
        for v in obj:
            yield from _iter_dicts(v, depth + 1)
    else:
        dump = getattr(obj, "model_dump", None)  # pydantic
        if callable(dump):
            try:
                yield from _iter_dicts(dump(), depth + 1)
                return
            except Exception:
                pass
        d = getattr(obj, "__dict__", None)
        if isinstance(d, dict) and d:
            yield from _iter_dicts(d, depth + 1)


# Destination tokens carried in the trusted goal text. IBAN-like and email
# recipients bind the transfer/effect tools; hosts and URLs bind network egress.
_IBAN_RE = re.compile(r"\b[A-Z]{2}[0-9A-Z]{6,32}\b")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_URL_HOST_RE = re.compile(r"https?://([^/\s]+)", re.I)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
# A file/resource explicitly named in the goal, e.g. 'bill-december-2023.txt'.
_NAMED_FILE_RE = re.compile(r"[\w.\-/]+\.[A-Za-z]{2,5}\b")


def _destinations_in(text: str) -> set[str]:
    """Every egress destination (IBAN or email) appearing in a text blob."""
    return set(_IBAN_RE.findall(text)) | set(_EMAIL_RE.findall(text))


def goal_destinations(query: str) -> tuple[set[str], set[str]]:
    """Provenance seed: the destinations that appear in the SEALED GOAL, the
    trusted user prompt captured before any tool output can contaminate it. An
    effect whose destination is not traceable to the goal came from untrusted
    context and is denied. This is the deployable replacement for oracle
    ground-truth seeding: same egress binding, but the trusted set is derived
    from the goal, not from the answer key. The attacker destination is never in
    the goal, so it is never authorized."""
    emails = set(_EMAIL_RE.findall(query))
    recipients = set(_IBAN_RE.findall(query)) | emails
    domains = set(_URL_HOST_RE.findall(query)) | set(_DOMAIN_RE.findall(query))
    # An email's own domain is a legitimate egress target for that contact.
    domains |= {e.split("@", 1)[1] for e in emails}
    return recipients, domains


class LiveBrokerHarness:
    """Holds the per-run broker and the per-task plan cache."""

    def __init__(self, mode: str, planner=None, recipient_map=None,
                 provenance: bool = False, taint: bool = False,
                 graduated: bool = False, defer: bool = False,
                 defer_allow: bool = False, audit_budget: int | None = None) -> None:
        self.graduated = graduated
        # Treat an intent-envelope plan miss as planner recall failure when the
        # destination-binding floor already cleared the action.
        self.defer = defer
        self.defer_allow = defer_allow
        # Cap on how often this session may interrupt the human. None = unlimited,
        # which is the historical behaviour and keeps prior results comparable.
        self.audit_budget = audit_budget
        self.mode = mode           # "floor" | "envelope"
        self.planner = planner
        # query -> set of authorized opaque recipients; enables egress recipient
        # binding (the argument-level defense for transfer-style tools).
        self.recipient_map = recipient_map
        # Deployable egress binding: seed the trusted destination set from the
        # goal text instead of the oracle recipient_map. Mutually exclusive with
        # recipient_map in practice; provenance is the shippable path.
        self.provenance = provenance
        # Origin-based taint: start from the goal seed, then WIDEN the trusted set
        # with recipients found in STRUCTURED fields of tool outputs as reads
        # happen (extract_recipients skips free-text fields, where the injection
        # hides). Recovers utility over goal-text-only without admitting the
        # attacker destination, which lives in free text.
        self.taint = taint
        self._egress: EgressPolicy | None = None
        self._plans: dict[str, tuple[list[str], object]] = {}
        self.broker: SessionBroker | None = None
        self.allows = 0
        self.blocks = 0
        self.runs = 0
        # Diagnostics: per-decision trace. `phase` is flipped by the driver
        # ("clean"/"attack") so each record knows which pass it came from.
        self.phase = "clean"
        self.query = ""
        self.decisions: list[dict] = []
        self._named: set[str] = set()  # files the user named in the goal

    def _plan(self, query: str, runtime):
        if query not in self._plans:
            tools = [(f.name, (getattr(f, "description", "") or "")) for f in runtime.functions.values()]
            if self.planner is not None:
                self._plans[query] = self.planner.plan(query, tools)
            else:
                self._plans[query] = ([n for n, _ in tools], None)  # allow-all, no plan
        return self._plans[query]

    def start_run(self, query: str, runtime) -> None:
        self.query = query
        # Resources the user explicitly named in the sealed goal. Only a unique
        # destination read DIRECTLY from one of these is trusted (see observe_output).
        self._named = set(_NAMED_FILE_RE.findall(query)) if self.taint else set()
        allowed, envelope = self._plan(query, runtime)
        goal = GoalSpec(query_id="live", summary=query,
                        allow_resources=[f"mcp:tool:{t}" for t in allowed])
        scope = TaskScope(allowed_resources=[f"mcp:tool:{t}" for t in allowed], allowed_actions=[])
        egress = None
        if self.provenance or self.taint:
            recips, domains = goal_destinations(query)
            egress = EgressPolicy(bind_recipients=True, allow_all=False,
                                  allowed_recipients=recips,
                                  allowed_domains=domains)
        elif self.recipient_map is not None:
            recips, domains = self.recipient_map.get(query) or (set(), set())
            egress = EgressPolicy(bind_recipients=True, allow_all=False,
                                  allowed_recipients=set(recips),
                                  allowed_domains=set(domains))
        self._egress = egress
        self.broker = SessionBroker(
            goal=goal, scope=scope, egress=egress,
            intent_envelope=(envelope if self.mode == "envelope" else None), detector=None,
            graduated=self.graduated, defer_to_binding=self.defer,
            defer_allows_bound=self.defer_allow, audit_budget=self.audit_budget)
        self.runs += 1

    def observe_output(self, result, source_args=None) -> None:
        """Origin-based taint: mine STRUCTURED recipient fields of a tool output
        and add them to the trusted egress set. The injection hides in free-text,
        which extract_recipients ignores, so a description-field attacker IBAN
        never enters the trusted set. This is sound and has held ASR at 0.

        FUNDAMENTAL LIMIT (measured, do not retry as a predicate tweak): trusting
        the FREE-TEXT of a goal-named resource is UNSAFE, because the injection is
        placed inside the very resource the user asks to read. The goal-named bill
        file 'bill-december-2023.txt' contains BOTH the legit recipient and the
        injected attacker IBAN as free-text, side by side. A deterministic check
        confirmed the attacker destination gets trusted (18 leaks, ASR 4.2%). No
        source-provenance predicate can separate two free-text tokens sharing one
        trusted source. So only STRUCTURED-field recipients are auto-trusted; a
        free-text recipient (task_0) is not auto-trustable and its correct
        handling is STEP_UP (graduated response, ask the human), not auto-trust."""
        if not self.taint or self._egress is None:
            return
        for d in _iter_dicts(result):
            for r in extract_recipients(d):
                self._egress.allowed_recipients.add(r)
        # Trust the UNIQUE destination in a resource the user NAMED in the goal,
        # and nothing else. Strictly scoped: only a read whose own arguments name a
        # goal-named file qualifies (so anything that file merely links to, or any
        # chained read of another file, never does), and only that read's own
        # returned content is scanned. Exactly one destination means the user
        # directed the agent to it; a second destination (an additive injection
        # placed in the same file) makes it non-unique, so nothing is trusted and
        # the effect steps up. This resolves the free-text limit above by refusing
        # on ambiguity rather than trying to separate two tokens with one origin.
        if self._named and source_args:
            target = " ".join(str(v) for v in source_args.values())
            if any(nm in target for nm in self._named):
                dests = _destinations_in(str(result))
                if len(dests) == 1:
                    self._egress.allowed_recipients |= dests

    def gate(self, tool_name: str, args: dict) -> tuple[bool, str]:
        action = Action(step=len(self.broker._trajectory.actions), tool=tool_name,
                        resource=f"mcp:tool:{tool_name}", verb=classify_verb(tool_name),
                        args=dict(args or {}))
        d = self.broker.authorize(action)
        allowed = d.outcome is Outcome.ALLOW  # DENY and STEP_UP both halt autonomous execution
        if allowed:
            self.allows += 1
        else:
            self.blocks += 1
        self.decisions.append(dict(
            phase=self.phase, query=self.query, tool=tool_name,
            args=dict(args or {}), outcome=d.outcome.name, layer=d.layer,
            reason=("; ".join(d.reasons) if d.reasons else d.layer)))
        return allowed, ("; ".join(d.reasons) if d.reasons else d.layer)


class BrokerToolsExecutor(ToolsExecutor):
    def __init__(self, harness: LiveBrokerHarness, tool_output_formatter=tool_result_to_str) -> None:
        super().__init__(tool_output_formatter)
        self.harness = harness

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        extra_args = {} if extra_args is None else extra_args
        messages = list(messages)
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1].get("tool_calls"):
            return query, runtime, env, messages, extra_args

        # New run detection: reset the broker on the first assistant turn.
        if self.harness.broker is None or sum(1 for m in messages if m["role"] == "assistant") == 1:
            self.harness.start_run(query, runtime)

        results = []
        for tc in messages[-1]["tool_calls"]:
            if tc.function == EMPTY_FUNCTION_NAME:
                results.append(_err(tc, "Empty function name provided."))
                continue
            if tc.function not in (t.name for t in runtime.functions.values()):
                results.append(_err(tc, f"Invalid tool {tc.function} provided."))
                continue
            for k, v in tc.args.items():
                if isinstance(v, str) and is_string_list(v):
                    tc.args[k] = literal_eval(v)
            allowed, reason = self.harness.gate(tc.function, tc.args)
            if not allowed:
                results.append(_err(tc, f"[BLOCKED by Clay Seal policy] {reason}. "
                                        "This action is not authorized for the current task."))
                continue
            result, error = runtime.run_function(env, tc.function, tc.args)
            # Trusted-origin widening: a read's structured output extends the
            # trusted destination set before any later effect action is gated.
            if error is None:
                self.harness.observe_output(result, source_args=tc.args)
            results.append(ChatToolResultMessage(
                role="tool", content=[text_content_block_from_string(self.output_formatter(result))],
                tool_call_id=tc.id, tool_call=tc, error=error))
        return query, runtime, env, [*messages, *results], extra_args


def _err(tc, message: str) -> ChatToolResultMessage:
    return ChatToolResultMessage(
        role="tool", content=[text_content_block_from_string("")],
        tool_call_id=tc.id, tool_call=tc, error=message)
