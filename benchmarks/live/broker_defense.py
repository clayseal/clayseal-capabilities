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

from clayseal.core.task_scope import TaskScope
from clayseal.capabilities.broker import Outcome, SessionBroker
from clayseal.capabilities.deployable_stack import DeployableStack
from clayseal.capabilities.hardening.egress_policy import (
    EgressPolicy, extract_recipients)
from clayseal.capabilities.monitor import Action
from clayseal.capabilities.scoping.goal import GoalSpec
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
# Country code + at least one digit (check digits). Without the digit
# requirement, injection markup like ``INFORMATION`` matched as an IBAN.
_IBAN_RE = re.compile(r"\b[A-Z]{2}[0-9][0-9A-Z]{4,30}\b")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_URL_HOST_RE = re.compile(r"https?://([^/\s]+)", re.I)
# The SAME host label class the egress policy uses to recognise a destination.
# When the two grammars disagree the goal cannot name a host the policy can
# match, and the site the user asked for is denied: 'www.resume_templates.com'
# is a dailylife goal, and the underscore-free class here returned nothing for
# it while the policy denied 'www.resume'.
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9_-]+\.)+[a-z]{2,}\b", re.I)
# Identity fields of the account a session is signed in as. This is session
# configuration, the same object a deployment reads to know whose mailbox it is
# holding, and it is not derived from the task, the ground truth or the attack.
_IDENTITY_KEYS = ("account_email", "account_id", "user_email", "logged_in_as")
_IDENTITY_VALUE_RE = re.compile(r"^[\w.+-]+@(?:[\w-]+\.)+[A-Za-z]{2,}$")


def session_identity(env) -> set[str]:
    """The identity this session acts as, read from the signed-in components.

    Read only from a component's OWN fields, never from a list of accounts
    nested inside one. That distinction is the whole safety of this function.
    An environment holds directories of other people, and these corpora put the
    attacker in one: a walk over every nested dict returns emma's address, her
    colleagues' addresses, `trustme@gmail.com` and `security_maintenance@gmail.com`
    together, and the caller uses this set to decide what is NOT egress. The
    session's own mailbox is a scalar on the mailbox component; every other
    address is a row in a directory it holds.
    """
    out: set[str] = set()
    root = env if isinstance(env, dict) else getattr(env, "model_dump", lambda: {})()
    if not isinstance(root, dict):
        return out
    for component in [root, *root.values()]:
        if not isinstance(component, dict):
            continue
        for key in _IDENTITY_KEYS:
            v = component.get(key)
            if isinstance(v, str) and _IDENTITY_VALUE_RE.match(v.strip()):
                out.add(v.strip())
    return out


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


def snapshot_trusted_files(env) -> dict[str, str]:
    """Pre-contamination file map from a clean environment load.

    Must be captured from ``load_and_inject_default_environment({})``, never
    from an attack-injected env: AgentDojo splices the attacker IBAN into
    goal-named bills (``injection_bill_text``), so seeding from the live env
    would authorize the attack.
    """
    if env is None:
        return {}
    fs = getattr(env, "filesystem", None)
    files = getattr(fs, "files", None) if fs is not None else None
    if isinstance(files, dict):
        return {str(k): str(v) for k, v in files.items() if isinstance(v, str)}
    return {}


def goal_named_env_destinations(
    query: str,
    clean_files: dict[str, str] | None,
) -> set[str]:
    """Destinations in clean snapshots of files the sealed goal named.

    Only files whose names appear in the goal are opened. Contents come from
    the pre-contamination snapshot, not from runtime tool output, so an
    injection spliced into the bill after task start never enters the seed.
    """
    if not clean_files:
        return set()
    named = set(_NAMED_FILE_RE.findall(query or ""))
    if not named:
        return set()
    out: set[str] = set()
    for name in named:
        text = clean_files.get(name)
        if text is None:
            base = name.rsplit("/", 1)[-1]
            text = clean_files.get(base)
        if text:
            out |= _destinations_in(text)
    return out


class LiveBrokerHarness:
    """Holds the per-run broker and the per-task plan cache."""

    def __init__(self, mode: str, planner=None, recipient_map=None,
                 provenance: bool = False, taint: bool = False,
                 graduated: bool = False, defer: bool = False,
                 defer_allow: bool = False, audit_budget: int | None = None,
                 replan: bool = False,
                 clean_files: dict[str, str] | None = None) -> None:
        self.graduated = graduated
        # Treat an intent-envelope plan miss as planner recall failure when the
        # destination-binding floor already cleared the action.
        self.defer = defer
        self.defer_allow = defer_allow
        # Cap on how often this session may interrupt the human. None = unlimited,
        # which is the historical behaviour and keeps prior results comparable.
        self.audit_budget = audit_budget
        # Runtime replanning: grow the plan from the sealed goal rather than
        # denying an unforeseen step. See clayseal/capabilities/replan.py.
        self.replan = replan
        # Parameter provenance: which observation supplied a value. Recorded
        # alongside taint so the two can be compared on the same runs. The taint
        # set answers "is this destination trusted"; provenance answers "which
        # tool produced it and was that tool an authorized source", which is the
        # axis the slack failure actually turns on.
        self._provenance = None
        self.mode = mode           # "floor" | "envelope"
        self.planner = planner
        # query -> set of authorized opaque recipients; enables egress recipient
        # binding (the argument-level defense for transfer-style tools).
        self.recipient_map = recipient_map
        # Deployable egress binding: seed the trusted destination set from the
        # goal text instead of the oracle recipient_map. Mutually exclusive with
        # recipient_map in practice; provenance is the shippable path.
        self.provenance = provenance
        self.hint_retries = 0
        self.hint_retry_hits = 0
        # Origin-based taint: start from the goal seed, then WIDEN the trusted set
        # with recipients found in STRUCTURED fields of tool outputs as reads
        # happen (extract_recipients skips free-text fields, where the injection
        # hides). Recovers utility over goal-text-only without admitting the
        # attacker destination, which lives in free text.
        self.taint = taint
        # Pre-contamination filesystem snapshot (suite defaults). Used only to
        # seed destinations from goal-named files; see goal_named_env_destinations.
        self.clean_files = dict(clean_files or {})
        self._egress: EgressPolicy | None = None
        self._plans: dict[str, tuple[list[str], object]] = {}
        self.broker: SessionBroker | None = None
        self.allows = 0
        self.blocks = 0
        self.runs = 0
        # Supervision accounting. `supervised_allows` counts actions that were
        # STEP_UP and became ALLOW only because a human answered, which is the
        # quantity the arithmetic `supervised` column has always assumed rather
        # than measured. `round_trips` is endorsements per completed action, the
        # metric endorsements-per-task cannot see.
        self.supervised_allows = 0
        self.round_trips = 0
        self.resolutions: list[dict] = []
        # Diagnostics: per-decision trace. `phase` is flipped by the driver
        # ("clean"/"attack") so each record knows which pass it came from.
        self.phase = "clean"
        self.query = ""
        self.decisions: list[dict] = []
        self._named: set[str] = set()  # files the user named in the goal
        self._identity: set[str] = set()  # accounts this session is signed in as

    def _plan(self, query: str, runtime):
        if query not in self._plans:
            tools = [(f.name, (getattr(f, "description", "") or "")) for f in runtime.functions.values()]
            if self.planner is not None:
                self._plans[query] = self.planner.plan(query, tools)
            else:
                self._plans[query] = ([n for n, _ in tools], None)  # allow-all, no plan
        return self._plans[query]

    def start_run(self, query: str, runtime, env=None) -> None:
        self.query = query
        # Who this session is signed in as. Supplied by the driver from session
        # configuration; absent, the egress policy behaves exactly as before.
        self._identity = session_identity(env) if env is not None else set()
        # Resources the user explicitly named in the sealed goal. Containing-
        # object provenance uses these as trust roots; free-text destinations
        # from them step up rather than auto-allow (see observe_output).
        self._named = (set(_NAMED_FILE_RE.findall(query))
                       if (self.taint or self.provenance) else set())
        allowed, envelope = self._plan(query, runtime)
        goal = GoalSpec(query_id="live", summary=query,
                        allow_resources=[f"mcp:tool:{t}" for t in allowed])
        scope = TaskScope(allowed_resources=[f"mcp:tool:{t}" for t in allowed], allowed_actions=[])
        egress = None
        if self.provenance or self.taint:
            recips, domains = goal_destinations(query)
            # Trusted environment provenance: IBANs/emails in the CLEAN copy of
            # files the user named. Never read the live/injected env here
            # banking attacks overwrite bill text with the attacker IBAN.
            env_recips = goal_named_env_destinations(query, self.clean_files)
            recips |= env_recips
            egress = EgressPolicy(bind_recipients=True, allow_all=False,
                                  allowed_recipients=recips,
                                  allowed_domains=domains,
                                  self_identifiers=set(self._identity))
        elif self.recipient_map is not None:
            recips, domains = self.recipient_map.get(query) or (set(), set())
            egress = EgressPolicy(bind_recipients=True, allow_all=False,
                                  allowed_recipients=set(recips),
                                  allowed_domains=set(domains),
                                  self_identifiers=set(self._identity))
        self._egress = egress
        # Fresh provenance graph per run, never carry destinations across tasks.
        if self.provenance or self.taint:
            from clayseal.capabilities.parameter_provenance import ParameterProvenance

            self._provenance = ParameterProvenance()
            # Index env-seeded destinations as structured observations of the
            # goal-named file so hint-retry / slot checks see the same trust roots.
            if self.clean_files and self._named:
                for name in self._named:
                    text = self.clean_files.get(name) or self.clean_files.get(
                        name.rsplit("/", 1)[-1])
                    if not text:
                        continue
                    for dest in _destinations_in(text):
                        self._provenance.record_observation(
                            "trusted_env", "",
                            structured_fields={"recipient": dest},
                            goal_named=True, containing_object=name)
        elif self._provenance is None:
            from clayseal.capabilities.parameter_provenance import ParameterProvenance

            self._provenance = ParameterProvenance()

        extender = None
        if self.replan and self.mode == "envelope" and self.planner is not None:
            from clayseal.capabilities.replan import PlanExtender, llm_shape_judge

            # The judge sees the SEALED goal and the tool catalog. It is
            # deliberately not given the envelope's plan, the trajectory, or any
            # tool output: the question is whether the goal implies this kind of
            # step, not whether the agent has talked itself into one.
            #
            # The catalog is the TOOLS THE SESSION HAS, not the subset the
            # planner guessed at. It used to be `sorted(allowed)`, and the floor
            # only consults the extender for a tool that is NOT in `allowed`, so
            # the judged tool was missing from the catalog it was judged against
            # 100% of the time, by construction. A judge asked whether a goal
            # needs a tool that does not appear in the list of available tools
            # has one sensible answer, and it is no.
            #
            # The catalog is static configuration, so widening it to the real
            # tool set moves no trust boundary: the judge still never sees an
            # argument value or a tool result, and the floor still binds every
            # destination underneath.
            extender = PlanExtender(
                judge=llm_shape_judge(self.planner.client, self.planner.model),
                goal=query,
                catalog=sorted(f.name for f in runtime.functions.values()))

        # Same DeployableStack profile as scoreboard / CTR replay. Soft plan
        # entailment when credentials exist (fail-open). Resource list is the
        # LLM planner's guess → scope_is_advisory=True (unlike mandate replay).
        stack = DeployableStack.from_goal(
            goal,
            scope=scope,
            egress=egress,
            intent_envelope=(envelope if self.mode == "envelope" else None),
            detector=None,
            graduated=self.graduated,
            defer_to_binding=self.defer,
            defer_allows_bound=self.defer_allow,
            audit_budget=self.audit_budget,
            plan_extender=extender,
            provenance=self._provenance,
            goal_named_objects=set(self._named),
            scope_is_advisory=True,
        )
        self.broker = stack.broker
        self.runs += 1

    def observe_output(self, result, source_args=None) -> None:
        """Origin-based taint + containing-object provenance.

        STRUCTURED recipient fields of a tool output widen the trusted egress
        set (injection hides in free text, which extract_recipients ignores).
        Free-text destinations are NEVER auto-trusted, even from a goal-named
        containing object, because the legit recipient and an injected attacker
        IBAN can sit side by side in one trusted file (measured ASR 4.2% when
        we auto-trusted unique free-text). Free-text of a goal-named object
        steps up via provenance on the authorize path instead.
        """
        containing = ""
        goal_named = False
        if source_args:
            target = " ".join(str(v) for v in source_args.values())
            for nm in self._named:
                if nm in target:
                    containing = nm
                    goal_named = True
                    break
            if not containing:
                containing = str(source_args.get("path")
                                 or source_args.get("file")
                                 or source_args.get("channel")
                                 or "")

        tool = ""
        if source_args:
            tool = str(source_args.get("_tool") or "")
        structured = {}
        for d in _iter_dicts(result):
            structured.update({k: v for k, v in d.items()
                               if isinstance(v, (str, int, float))})
        # Prefer the broker's observe path so authorize and provenance share one
        # index; fall back to the harness index when no broker is up yet.
        if self.broker is not None:
            src_path = ""
            if source_args:
                for key in ("path", "file_path", "filename", "file"):
                    v = source_args.get(key)
                    if isinstance(v, str) and v:
                        src_path = v
                        break
            self.broker.observe_output(
                tool or "tool", result, structured_fields=structured,
                goal_named=goal_named, containing_object=containing,
                source_path=src_path,
                source_args=dict(source_args or {}))
            # Expanding Edit → line-shift for absolute-line sed checks.
            if (source_args or {}).get("_tool") == "Edit" or (
                isinstance(source_args, dict)
                and ("old_string" in source_args and "new_string" in source_args)
            ):
                ep = src_path or str(
                    (source_args or {}).get("file_path")
                    or (source_args or {}).get("path")
                    or ""
                )
                self.broker.note_edit(
                    ep,
                    str((source_args or {}).get("old_string") or ""),
                    str((source_args or {}).get("new_string") or ""),
                )
        elif self._provenance is not None:
            self._provenance.record_observation(
                tool or "tool", result, structured_fields=structured,
                goal_named=goal_named, containing_object=containing)

        if self._egress is None:
            return
        # Widen allow-list from structured recipient fields so a later
        # re-audited hint-retry can ALLOW (provenance alone only STEP_UPs).
        # - taint: any structured read (origin-based)
        # - provenance without taint: only goal-named containing objects
        # Free text is never mined here (injection channel).
        if not self.taint and not (self.provenance and goal_named):
            return
        for d in _iter_dicts(result):
            for r in extract_recipients(d):
                self._egress.allowed_recipients.add(r)
    def gate_with_supervision(self, tool_name: str, args: dict,
                             approver=None, max_round_trips: int = 2
                             ) -> tuple[bool, str]:
        """`gate`, but a STEP_UP is a question rather than a halt.

        `gate` collapses the three outcomes to `allowed = outcome is ALLOW`, with
        the comment that DENY and STEP_UP both halt autonomous execution. True
        for an autonomous run, and it is why "supervised utility" has always been
        arithmetic: `summarize_ladder` adds the step-up losses back and assumes
        both that a human would have said yes and that the task then succeeded.
        The second assumption is unchecked and is the likely reason the measured
        delta will come out NEGATIVE.

        Here the approver actually answers, the approval goes through
        `SessionBroker.resolve_step_up` (real signature verification, single use,
        bound to this exact action), and the SAME action is re-authorized. A
        second step-up for a *different* rule is a genuine second question and is
        allowed to happen; `max_round_trips` bounds it at 2, because a rule that
        needs three rounds to clear one action is a defect the endorsements-per-
        task metric cannot see.
        """
        action = Action(step=len(self.broker._trajectory.actions), tool=tool_name,
                        resource=f"mcp:tool:{tool_name}", verb=classify_verb(tool_name),
                        args=dict(args or {}))
        round_trips = 0
        decision = self.broker.authorize(action)
        while (approver is not None
               and decision.outcome is Outcome.STEP_UP
               and decision.step_up is not None
               and round_trips < max_round_trips):
            signed = approver.review(decision.step_up)
            if signed is None:
                break                      # the human declined; the step-up stands
            resolved, why = self.broker.resolve_step_up(signed)
            self.resolutions.append({"query": self.query, "tool": tool_name,
                                     "resolved": resolved, "reason": why,
                                     "round": round_trips + 1})
            if not resolved:
                break
            round_trips += 1
            decision = self.broker.authorize(action)

        allowed = decision.outcome is Outcome.ALLOW
        if allowed:
            self.allows += 1
        else:
            self.blocks += 1
        if round_trips:
            self.supervised_allows += int(allowed)
            self.round_trips += round_trips
        reason = "; ".join(decision.reasons) if decision.reasons else decision.layer
        self.decisions.append(dict(
            phase=self.phase, query=self.query, tool=tool_name,
            args=dict(args or {}), outcome=decision.outcome.name,
            layer=decision.layer, reason=reason, round_trips=round_trips,
            resolved_by=getattr(approver, "name", None) if round_trips else None,
        ))
        return allowed, reason

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
        reason = "; ".join(d.reasons) if d.reasons else d.layer
        if not allowed and d.trusted_candidates:
            # ARGUS-style: tell the agent which grounded recipients it may retry.
            hint = ", ".join(d.trusted_candidates[:5])
            reason = f"{reason}. trusted_candidates=[{hint}]"
        self.decisions.append(dict(
            phase=self.phase, query=self.query, tool=tool_name,
            args=dict(args or {}), outcome=d.outcome.name, layer=d.layer,
            reason=reason,
            trusted_candidates=list(d.trusted_candidates)))
        return allowed, reason


class BrokerToolsExecutor(ToolsExecutor):
    def __init__(
        self,
        harness: LiveBrokerHarness,
        tool_output_formatter=tool_result_to_str,
        *,
        auto_retry_hints: bool = True,
    ) -> None:
        super().__init__(tool_output_formatter)
        self.harness = harness
        # ARGUS-style: one re-audited retry with a grounded destination when the
        # floor attached trusted_candidates. Default on, pure utility, no
        # bypass (retry goes through gate/authorize again).
        self.auto_retry_hints = auto_retry_hints

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        from clayseal.capabilities.retry_hints import reaudited_retry

        extra_args = {} if extra_args is None else extra_args
        messages = list(messages)
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1].get("tool_calls"):
            return query, runtime, env, messages, extra_args

        # New run detection: reset the broker on the first assistant turn.
        if self.harness.broker is None or sum(1 for m in messages if m["role"] == "assistant") == 1:
            self.harness.start_run(query, runtime, env=env)

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
            if not allowed and self.auto_retry_hints:
                last = self.harness.decisions[-1] or {}
                cands = list(last.get("trusted_candidates") or [])
                # Only worth retrying destination misses. Envelope/scope blocks
                # still attach candidates, but rewriting `to` cannot clear them.
                reason_l = (last.get("reason") or reason or "").lower()
                egress_miss = (
                    last.get("layer") == "floor"
                    and any(tok in reason_l for tok in (
                        "egress", "recipient", "allow-list", "destination",
                        "not on allow", "ungrounded", "no observation",
                        "free text", "untrusted containing",
                    ))
                )
                if cands and egress_miss:
                    self.harness.hint_retries += 1
                    ok, reason2, rewritten, used = reaudited_retry(
                        self.harness.gate, tc.function, tc.args, cands)
                    if ok and used is not None:
                        self.harness.hint_retry_hits += 1
                        tc.args = rewritten
                        allowed, reason = True, reason2
            if not allowed:
                results.append(_err(tc, f"[BLOCKED by Clay Seal policy] {reason}. "
                                        "This action is not authorized for the current task. "
                                        "If trusted_candidates are listed, retry with one of them."))
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
