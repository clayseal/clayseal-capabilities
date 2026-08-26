"""SessionBroker — the one gateway the memo describes.

The library had two strong but separate halves: the per-action enforcement floor
(scope, protected zones, egress, budgets, argument binding) and the behavioral
detector (envelope, taint, AML, CUSUM, conformal scorer). The memo describes a
single gateway: "the agent has to ask for authority at the point where it is
about to do something real," and that gateway both binds the action and watches
the stream. This composes both into one online decision per action, over a live
session, and speaks the metrics and step-up vocabulary the rest of the system
already defines.

Decision order, cheap-hard to expensive-soft:

1. Per-action floor (hard deny): protected zones, path/resource/action scope,
   egress policy, budget reservation. A floor denial is recorded as a prevented
   violation and never reaches the behavioral layer.
2. Behavioral detector (trajectory): the floor-allowed action is appended to the
   running trajectory and the detector re-assesses. A structural block denies; a
   soft escalation raises a step-up request instead of a hard deny.

Every outcome updates a ``ScopingMetrics`` (prevented violations, monitor
triggers, broker overhead), so the containment/friction picture is available at
runtime, not only offline in the benchmark.
"""
from __future__ import annotations

from dataclasses import replace as _dc_replace
from datetime import datetime, timezone


def _utcnow():
    return datetime.now(timezone.utc)

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from uuid import uuid4

from agentauth.capabilities.call_budget import SessionCallBudget
from agentauth.capabilities.decision_log import DecisionLog
from agentauth.capabilities.hardening.egress_policy import EgressPolicy
from agentauth.capabilities.hardening.protected_zones import (
    is_protected_path,
    protected_reason,
)
from agentauth.capabilities.monitor import (
    Action,
    ContextItem,
    Decision,
    IntentEnvelope,
    Trajectory,
    TrajectoryDetector,
    is_consequential,
)
from agentauth.capabilities.monitor.intent_envelope import Deviation
from agentauth.capabilities.replan import verb_class
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.capabilities.scoping.metrics import ScopingMetrics
from agentauth.capabilities.session_grants import GrantSource, SessionGrants
from agentauth.capabilities.step_up import (
    StepUpRequest,
    bind_to_action,
    build_step_up_request,
    verify_step_up_approval,
)
from agentauth.capabilities.value_budget import SessionValueBudget
from agentauth.core.hash_util import hash_canonical_json
from agentauth.core.operations import capability_allows, normalize_capabilities
from agentauth.core.task_scope import TaskScope, task_scope_allows_path


class Outcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    STEP_UP = "step_up"


@dataclass(frozen=True)
class BrokerDecision:
    outcome: Outcome
    layer: str                       # "floor" | "behavioral" | "-"
    reasons: tuple[str, ...] = ()
    step_up: StepUpRequest | None = None
    record: dict[str, Any] | None = None  # tamper-evident decision record (L3 sink)
    # Structured-field values the provenance graph trusts. Attached on egress
    # deny / step-up so a blocked agent can retry with a grounded recipient
    # (ARGUS-style). Empty when provenance is off or nothing is grounded.
    trusted_candidates: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.outcome is Outcome.ALLOW


_WRITE_ACTIONS = {"write", "create", "update", "delete", "send", "transfer", "post", "pay"}
_EGRESS_ACTIONS = {"send", "post", "transfer", "share"}


def _action_path(action: Action) -> str | None:
    # Prefer meta path (loaders often resolve cwd-relative args to absolute).
    meta_path = (action.meta or {}).get("path")
    if isinstance(meta_path, str) and meta_path:
        return meta_path
    for key in ("file_path", "path", "filename", "file"):
        v = action.args.get(key)
        if isinstance(v, str) and v:
            return v
    for scheme in ("repo_write://", "repo_read://", "repo://", "file:"):
        if action.resource.startswith(scheme):
            return action.resource[len(scheme):].lstrip("/")
    return None


@dataclass
class SessionBroker:
    """Live per-session gateway composing the floor and the behavioral detector."""

    goal: GoalSpec
    scope: TaskScope | None = None
    # Primary, history-free behavioral tier (RSS-style). Compiled from the sealed
    # goal; when present it is the main conformance check and the statistical
    # detector is demoted to a sensor via the two-signal gate.
    intent_envelope: IntentEnvelope | None = None
    detector: TrajectoryDetector | None = None
    egress: EgressPolicy | None = None
    value_budget: SessionValueBudget | None = None
    call_budget: SessionCallBudget | None = None
    escalate_on_soft: bool = True   # detector ESCALATE -> step-up (else allow)
    # Formally scope the statistical detector as ADVISORY: it never hard-blocks on
    # its own, only escalates for review. The sensor is validated (AUC 0.91 on real
    # fraud) but too noisy on sparse agent trajectories to be a primary blocker, so
    # safety rests on the envelope and floor, per the runtime-assurance design.
    detector_advisory: bool = False
    # Graduated response (opt-in): demote an egress destination miss from hard
    # DENY to STEP_UP. An unknown destination is ambiguous between an injected
    # attacker address and a legitimate one the agent read from a document, and
    # the two are indistinguishable when they share a source. STEP_UP halts the
    # attacker autonomously (ASR unchanged) and lets a human confirm the benign
    # send under supervision, which is the honest response to that ambiguity and
    # the desirable UX for a novel payee. Default off keeps the hard-deny.
    graduated: bool = False
    #: Refuse a consequential action whose payload carries a credential-shaped
    #: value. Opt-in, but its false-positive rate is measured rather than
    #: assumed: 0 of 761 benign string arguments across the whole BPL corpus,
    #: 97.5% upper bound 0.5%. See `hardening/secret_content.py`.
    refuse_credential_payloads: bool = False
    # Defer to binding (opt-in): when the destination-binding floor is active and
    # the action cleared it, treat an intent-envelope plan miss as a planner
    # recall failure rather than as evidence of an attack.
    #
    # Why this is safe, and why it is worth doing. The floor runs first, so any
    # action reaching the envelope is already in scope, within budget, and
    # argument-bound, and under provenance/taint its destination traces to the
    # sealed goal. The envelope's remaining objection is "the LLM planner did not
    # list this step". That is a statement about the planner's recall, not about
    # the action.
    #
    # It is also the single most expensive rule we run: across four models and
    # four suites, `off-plan and consequential` accounts for 100% of the hard
    # false blocks on the shippable path, and 10 of its 11 denials turned a task
    # that would have succeeded into one that failed.
    #
    # The security argument is the provenance thesis restated: an injected step's
    # destination is not in the sealed goal, so it never clears the binding floor
    # and never reaches this gate. Deferring here therefore gives up nothing the
    # floor was not already catching, which is a claim to verify by measurement
    # rather than assert — see benchmarks/results/deferred_envelope.md.
    defer_to_binding: bool = False
    # The stronger form: for an action whose destination the floor positively
    # validated, allow rather than step up.
    #
    # MEASURED NEGATIVE RESULT — do not enable. The motivating argument was that
    # an injected step's destination never clears the binding floor, so this gate
    # catches nothing the floor missed. That holds on banking (ASR 0.0% with and
    # without) and is FALSE on travel, where enabling it took ASR from 5.6% to
    # 27.8% and dropped blocks from 17 to 3. The intent envelope's plan-
    # conformance check does real containment work wherever the injected action
    # reaches a destination the floor finds acceptable.
    #
    # Kept, defaulted off, and documented rather than deleted: the flag is how
    # the result reproduces. See benchmarks/results/denial_diagnosis.md.
    defer_allows_bound: bool = False
    # Audit budget: how many times this session may interrupt the human.
    #
    # The control literature treats human attention as the scarce resource a
    # protocol spends, and we have been treating it as free. That is why an
    # oracle configuration can post 84% supervised utility at 0.72 endorsements
    # per task and be reported as a win: nobody was charged for the 0.72.
    #
    # It is also a security property, not only a UX one. A step-up policy is
    # attackable by exhaustion — issue enough benign-looking confirmations and
    # the human stops reading — so an unbounded step-up count is an unbounded
    # attack surface. With a budget, exceeding it is a decision the system has
    # to make explicitly rather than a slope it slides down.
    #
    # None means unlimited, which is the current behaviour and stays the default
    # so this does not silently change existing results.
    # Runtime replanning. When the intent envelope reports a deviation, ask
    # whether the sealed goal plausibly requires an action of this SHAPE, and if
    # so extend the plan rather than deny. The extender sees the goal, the tool
    # catalog and the shape; never tool output and never argument values, which
    # is what keeps an injection out of the decision. See
    # agentauth/capabilities/replan.py for the trust argument, and
    # benchmarks/results/agentdyn.md for the failure that motivated it (zero
    # clean utility on open-ended tasks).
    #
    # This is NOT `defer_allows_bound`, which dropped the shape check and cost
    # 22 points of ASR. The shape check survives here; only the plan it is
    # checked against may grow.
    plan_extender: Any | None = None
    # Whether `scope.allowed_resources` is a PLANNER GUESS rather than an
    # operator grant. This distinction decides whether replanning may widen it,
    # and nothing in the code expressed it until a security test caught the
    # ambiguity.
    #
    # In the live path the resource list is built from the LLM planner's guess at
    # which tools the task needs, so a missing tool is a recall failure and
    # extending it from the sealed goal is legitimate. Where the list comes from
    # a signed mandate it is an authorization, and no runtime judgment may widen
    # it. Default False keeps mandate-derived scopes rigid, so a caller has to
    # opt in by asserting the weaker provenance.
    scope_is_advisory: bool = False
    # Independent cap on how many (resource, verb class) pairs replanning may
    # admit. `PlanExtender.max_extensions` bounds SHAPES, and one shape admits
    # unlimited resources, so without this a single "the goal may write" verdict
    # let every write target in the catalog through.
    max_scope_extensions: int = 8
    # WHOSE authority this action is. Absent means a single-principal session,
    # and the rung is a pass-through, so adding this changes nothing for an
    # existing caller.
    #
    # `deputy.DelegationBoundary` contained 100% of sub-agent overreach in the
    # benchmark and had no runtime input: it reads a principal that nothing
    # populated. Any orchestrator knows which sub-agent issued a call, so the
    # gap was plumbing rather than information, and this is the plumbing. The
    # acting principal is read from `action.meta["principal"]` and the
    # credential it presented from `delegation_envelopes`.
    delegation: Any | None = None
    delegation_envelopes: dict[str, Any] = field(default_factory=dict)
    # COMMIT-THEN-REVEAL. The actions the agent said it was going to take, sealed
    # before it takes any of them.
    #
    # The twin corridor in `monitor/sealed_plan.py` contains covert sabotage that
    # every per-action rung misses, and it had no runtime input: it needs a clean
    # run of the same task, which a benchmark ships and a deployment never has.
    # A DECLARATION is the same shape of object and the agent produces it, so a
    # deployment does have one.
    #
    # Measured on the case that matters, an agent that declares an honest backup
    # and then adds an exfil copy at execution:
    #
    #     declared honestly, executed honestly     no flags
    #     declared honestly, then sabotaged        destination not in sealed plan
    #
    # The limit is equally clear: an agent that DECLARES the sabotage passes the
    # corridor, and the declaration then carries the attacker's destination in
    # static text available before anything runs, which is a far easier object to
    # judge than a trajectory. That is the trade this makes, and it is why the
    # declaration should itself be checked against the sealed goal.
    #
    # None means no declaration, and the corridor stays off, so an existing
    # caller is unchanged.
    declared_plan: Trajectory | None = None
    # Containing-object provenance (AuthGraph-shaped). Which observation supplied
    # an opaque destination, and was that observation an authorized source.
    # The live harness already recorded observations; the floor used to call
    # bare ``egress.check`` and ignore this, so a grounded recipient discovered
    # at runtime could only hard-deny. When set, misses consult
    # ``EgressPolicy.check_with_provenance`` (structured → step-up, free-text of
    # a goal-named object → step-up, else deny).
    provenance: Any | None = None
    goal_named_objects: set[str] = field(default_factory=set)
    # Injectable so expiry is testable and so a replay can pin a moment. Defaults
    # to real UTC now, which is what a deployment wants.
    clock: Callable[[], Any] = field(
        default_factory=lambda: (lambda: __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc)))
    audit_budget: int | None = None
    # What to do once the budget is spent. Denying is the conservative choice and
    # keeps the security claim intact at the cost of utility; allowing trades the
    # other way and must never be the default.
    on_audit_exhausted: str = "deny"   # "deny" | "allow"
    #: `on_audit_exhausted="allow"` is a fail-open on the authorization path and
    #: must be opted into deliberately, not inherited from a config default. A
    #: caller that has not acknowledged it gets the safe branch regardless.
    allow_on_exhaust_acknowledged: bool = False
    #: How long a step-up request stays answerable.
    step_up_ttl_seconds: int = 600
    #: Requests this session issued, by commitment. An approval answering a
    #: request we never asked is rejected before any signature work.
    _pending: dict = field(default_factory=dict, repr=False)
    #: Approval ids already spent, so one approval clears one action.
    _consumed: set = field(default_factory=set, repr=False)
    #: Authority acquired at runtime, from any source. See session_grants.py.
    grants: SessionGrants = field(default_factory=SessionGrants)
    #: Content-derivation tracking. Composes `provenance` and answers a question
    #: parameter provenance cannot: does THIS write carry a value that came from
    #: a sensitive read, however it was reshaped on the way out.
    #:
    #: Wired as a STEP_UP layer, never a DENY layer, and that is a measurement
    #: rather than caution. `benchmarks/results/flow_window.md`: after the write
    #: windowing the tracker refuses nothing at all on real benign traffic
    #: (0 of 1,242 events) and closes the cheapest split there is (two writes,
    #: 200/200 -> 0/200), but wide splits stay open (22 fragments out of order,
    #: 162/200) and unkeyed encodings are open at every width (base85, decimal
    #: byte codes, 100/100). Sound where it fires, incomplete in what it catches.
    #: A layer with those properties should ask, not refuse.
    flow: Any = None
    sensitivity: Any = None
    audits_spent: int = 0
    #: Serialises the whole mutating surface of a session.
    #:
    #: Every field this class mutates — the trajectory, `_pending`,
    #: `_consumed`, `audits_spent`, `grants`, `session`, `_extended_pairs`, the
    #: decision chain — was unsynchronised, and an agent gateway is concurrent by
    #: construction: one session issues several tool calls at once. Two of those
    #: races lose a control rather than a value.
    #:
    #: `audits_spent` is a read-modify-write on the human-attention ceiling, so
    #: two step-ups racing past a budget of one both charge and both ask.
    #: `_consumed` is the single-use ledger for approvals, so the same approval
    #: verified twice concurrently clears two actions. Both are the exact
    #: check-then-act shape `value_budget.reserve` already takes a lock for.
    #:
    #: Re-entrant because `authorize` calls `_finalize`, which calls into the
    #: metrics and the decision log, and `resolve_step_up` reads `_pending`
    #: while holding it.
    _lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)
    metrics: ScopingMetrics = field(default_factory=ScopingMetrics)
    decision_log: DecisionLog = field(default_factory=DecisionLog)
    receipt_sink: Callable[[dict[str, Any]], None] | None = None
    #: W3C Trace Context for the work this session is part of, stamped onto
    #: every decision record so a receipt joins to the trace that produced it.
    #: Set per request in a stateless deployment, once per session otherwise.
    trace: Any = None
    #: Decisions the evidence plane could not account for: an audit append or a
    #: receipt sink raised. Never silently zero, and a deployment should alert on
    #: it, because an unlogged decision is an unauditable one.
    unrecorded_decisions: int = field(default=0, init=False)
    #: Telemetry calls that raised. Counted for the same reason and separated
    #: because losing a metric is not losing evidence.
    telemetry_failures: int = field(default=0, init=False)
    _trajectory: Trajectory = field(init=False)
    # Fail-closed reasons from check_declaration_against_goal. Populated once
    # when a declaration is present; every authorize() then denies.
    _declaration_denials: tuple[str, ...] = field(default_factory=tuple, init=False)
    # Soft entailment advisories from an optional plan-level judge (ARGUS-shaped).
    # Never fail closed; first consequential authorize steps up instead.
    entailment_judge: Any | None = None
    # Wall-clock ceiling on the judge, enforced by the broker rather than trusted
    # to the judge. The judge is a remote model called on the authorization path
    # while this session's lock is held, so an endpoint that stops answering must
    # cost a bounded pause and one lost advisory, not a stalled session. None
    # takes `llm_clients.DEFAULT_TOTAL_BUDGET`.
    judge_budget_seconds: float | None = None
    _declaration_advisories: tuple[str, ...] = field(default_factory=tuple, init=False)
    # Compiled constraints from an accepted declaration (argv / digest / callee).
    # Used at authorize time so honest_declare→sabotage is on the gateway, not
    # only in offline twin helpers.
    _sealed_plan: Any | None = field(default=None, init=False)
    # Cross-turn product memory (symlink/CSV/line-map/sealed-violation taints).
    # One object for scoreboard / CTR / live — not per-corpus caches.
    session: Any = field(default=None)
    #: Run the corpus-derived session rule pack (`session_rules.py`).
    #:
    #: OFF here and ON in `DeployableStack.from_goal`, and the split is the
    #: point. Those five rules are pattern matches written against specific
    #: benchmark sabotage scenarios — one of them carries a corpus's project name
    #: as a literal — so they belong to the measured profile, not to the library
    #: primitive. Every published containment number was produced with them on,
    #: which is why the profile keeps them on and says so rather than quietly
    #: changing what the scoreboard reproduces.
    #:
    #: A deployment on a workload that does not look like those corpora should
    #: measure both ways. They only ever STEP_UP, so the cost of leaving them on
    #: is friction rather than blocked work.
    session_rules: bool = False
    # Ladder-parity floor grants (same checks as TaskScopeInputBindingEngine).
    # Empty/None keeps prior broker behaviour for callers that only set scope.
    allowed_tools: set[str] | None = None
    #: Tools the grant admits only while a condition holds. Withdraws from
    #: `allowed_tools` and never adds, so a fact an attacker can assert can only
    #: reduce authority. See `conditional_ceiling.ConditionalTools`.
    conditional_tools: Any = None
    tool_patterns: list[str] | None = None
    capabilities: list[dict[str, str]] | None = None
    # tool -> set of authorized argument hashes (commit-token binding).
    authorized_arg_hashes: dict[str, set[str]] | None = None
    # Soft: require a prior commit_plan before egress verbs (STEP_UP if missing).
    # Off by default — coding corpora see high friction; opt in for mail/MCP.
    require_declaration_for_egress: bool = False

    def __post_init__(self) -> None:
        from agentauth.capabilities.session_memory import SessionMemory

        if self.session is None:
            self.session = SessionMemory()
        if self.entailment_judge is not None:
            # Bound whatever was supplied, including a caller's own callable.
            # Doing it here rather than at the construction site is what makes
            # the ceiling a property of the gateway instead of a convention the
            # next integration can forget.
            from agentauth.capabilities.monitor.llm_clients import bounded

            self.entailment_judge = bounded(
                self.entailment_judge, budget_seconds=self.judge_budget_seconds
            )
        self._trajectory = Trajectory(goal=self.goal, actions=[], context=[])
        self.metrics.goal_id = self.goal.query_id
        self._seed_goal_provenance()
        if self.declared_plan is not None:
            self._commit_plan_locked(self.declared_plan)

    # Backward-compatible aliases (tests / broker_eval still use private names).
    @property
    def _symlink_taints(self):
        return self.session.symlink_taints

    @_symlink_taints.setter
    def _symlink_taints(self, value) -> None:
        self.session.symlink_taints = value

    @property
    def _sealed_violation_taint(self) -> bool:
        return self.session.sealed_violation

    @_sealed_violation_taint.setter
    def _sealed_violation_taint(self, value: bool) -> None:
        self.session.sealed_violation = bool(value)

    @property
    def _csv_columns(self):
        return self.session.csv_columns

    @_csv_columns.setter
    def _csv_columns(self, value) -> None:
        self.session.csv_columns = value

    @property
    def _file_text(self):
        return self.session.file_text

    @_file_text.setter
    def _file_text(self, value) -> None:
        self.session.file_text = value

    @property
    def _file_line_shift(self):
        return self.session.file_line_shift

    @_file_line_shift.setter
    def _file_line_shift(self, value) -> None:
        self.session.file_line_shift = value

    def _seed_goal_provenance(self) -> None:
        """Record destinations named in the sealed goal as structured observations.

        Without this, a TRUSTED_READ slot fails even for ``bob@corp.example``
        when the prompt itself named him — the allow-list admits the send and
        the slot check then denies for "no observation". The sealed goal is the
        one pre-contamination source that is always admissible.
        """
        if self.provenance is None:
            return
        summary = self.goal.summary or ""
        structured: dict[str, str] = {}
        try:
            from agentauth.capabilities.hardening.egress_policy import (
                extract_email_addresses,
            )
            for i, email in enumerate(extract_email_addresses({"to": summary})):
                structured[f"goal_email_{i}"] = email
        except Exception:  # noqa: BLE001, S110 - seeding is best-effort
            # Deliberately total and deliberately silent. This runs in
            # `__post_init__`: a goal summary that defeats the address extractor
            # must not prevent the broker from being constructed, and the only
            # consequence of the miss is that a goal-named recipient earns a
            # STEP_UP instead of an ALLOW — the safe direction.
            pass
        import re
        for i, m in enumerate(re.findall(r"\b[A-Z]{2}[0-9A-Z]{10,30}\b", summary)):
            structured[f"goal_iban_{i}"] = m
        if not structured and not summary.strip():
            return
        self.provenance.record_observation(
            "sealed_goal", summary,
            structured_fields=structured or None,
            goal_named=True,
            containing_object="sealed_goal",
        )

    def _commit_plan_locked(self, plan: Trajectory) -> list[str]:
        """Seal a commit-then-reveal declaration before any side effect.

        Returns goal-check denial reasons (empty ⇒ accepted). The plan is also
        the twin-corridor reference for later ``authorize`` calls. A non-empty
        result fails closed: every subsequent authorize denies.

        When ``entailment_judge`` is set, also runs a soft plan-level entailment
        check (content/meaning). Conflicts become ``_declaration_advisories`` and
        step up on the first consequential authorize — they never hard-deny.

        An accepted plan is compiled into ``_sealed_plan`` so later authorize
        calls can STEP_UP on argv/digest/callee drift vs the declaration
        (deployable twin corridor — no gifted clean twin required).
        """
        from agentauth.capabilities.monitor.declaration import (
            check_declaration_against_goal,
        )
        from agentauth.capabilities.monitor.entailment import assess_plan_entailment
        from agentauth.capabilities.monitor.sealed_plan import compile_sealed_plan

        self.declared_plan = plan
        reasons = check_declaration_against_goal(plan, self.goal)
        self._declaration_denials = tuple(reasons)
        # Soft advisories (deterministic ∪ optional LLM) even when the
        # destination goal-check passes. Never hard-deny.
        if not reasons:
            advisory = assess_plan_entailment(
                plan, self.goal.summary or "", self.entailment_judge)
            self._declaration_advisories = advisory.reasons if advisory.escalate else ()
            self._sealed_plan = compile_sealed_plan(plan)
        else:
            self._declaration_advisories = ()
            self._sealed_plan = None
        return reasons

    # -- concurrency --------------------------------------------------------
    #
    # One session, several in-flight tool calls, is the ordinary shape of an
    # agent gateway. Every method below mutates session state, so each takes the
    # session lock and delegates to a `_*_locked` implementation. Splitting it
    # this way rather than sprinkling `with self._lock:` through the bodies means
    # a new mutating path cannot be added without either going through a facade
    # or being conspicuously outside one.

    def authorize(self, action: Action) -> BrokerDecision:
        with self._lock:
            return self._authorize_locked(action)

    def resolve_step_up(self, approval) -> tuple[bool, str]:
        with self._lock:
            return self._resolve_step_up_locked(approval)

    def commit_plan(self, plan: Trajectory) -> list[str]:
        with self._lock:
            return self._commit_plan_locked(plan)

    def reclear(self, envelope: IntentEnvelope | None = None, *,
                signed: dict | None = None, trusted_keys=None) -> bool:
        with self._lock:
            return self._reclear_locked(
                envelope, signed=signed, trusted_keys=trusted_keys)

    def observe_context(self, item: ContextItem) -> None:
        with self._lock:
            self._observe_context_locked(item)

    def observe_output(self, *args: Any, **kwargs: Any) -> None:
        with self._lock:
            self._observe_output_locked(*args, **kwargs)

    def note_edit(self, path: str, old: str, new: str) -> None:
        with self._lock:
            self._note_edit_locked(path, old, new)

    # -- re-clearance (ATC) --------------------------------------------------
    def _reclear_locked(self, envelope: IntentEnvelope | None = None, *,
                signed: dict | None = None, trusted_keys=None) -> bool:
        """Adopt a new sealed envelope mid-session, the way Air Traffic Control
        issues a fresh clearance for a route change rather than letting the pilot
        improvise. The control plane regenerates and re-signs on trusted input
        when the task legitimately grows; the broker verifies and swaps it. Prior
        actions stay judged under the envelope they were cleared under; new
        actions are judged under the new one. The swap is recorded on the audit
        chain."""
        from agentauth.capabilities.monitor import verify_intent_envelope

        if signed is not None:
            ok, reason = verify_intent_envelope(signed, trusted_keys=trusted_keys)
            if not ok:
                self.decision_log.append(
                    query_id=self.goal.query_id, tool="<reclearance>", resource="-",
                    action_verb="reclear", arguments_hash="-", outcome="deny",
                    layer="control-plane", reasons=(f"re-clearance rejected: {reason}",))
                return False
            envelope = IntentEnvelope.from_dict(signed["document"])
        if envelope is None:
            return False
        self.intent_envelope = envelope
        self.decision_log.append(
            query_id=self.goal.query_id, tool="<reclearance>", resource="-",
            action_verb="reclear", arguments_hash="-", outcome="allow",
            layer="control-plane", reasons=("envelope re-cleared",))
        return True

    # -- provenance ----------------------------------------------------------
    def _observe_context_locked(self, item: ContextItem) -> None:
        """Register a piece of context the agent has been exposed to.

        Callers push tool output here, tagged ``TrustLevel.UNTRUSTED``, so the
        behavioral layer can tell an action justified by the sealed goal from
        one justified by something the agent read at runtime. Untrusted-derived
        actions are what :class:`TaintTracker` keys on.

        This is the supported way in: an ``Action`` is frozen and carries no
        context of its own, so provenance has to arrive alongside it rather than
        inside it.
        """
        self._trajectory.context = [*self._trajectory.context, item]

    def _observe_output_locked(
        self,
        tool: str,
        payload: Any,
        *,
        structured_fields: dict[str, Any] | None = None,
        goal_named: bool = False,
        containing_object: str = "",
        source_path: str = "",
        source_args: dict | None = None,
    ) -> None:
        """Record which observation supplied which values (parameter provenance).

        Call after a tool returns, before the next ``authorize``. Without this,
        ``check_with_provenance`` has nothing to ground destinations against and
        every novel recipient hard-denies — the banking utility cliff.

        When ``source_path`` is a CSV and ``payload``'s first line looks like a
        header, also bind column names for later awk ``$N`` checks. Read
        payloads with ``N→`` line prefixes update the session file text used
        by absolute-line sed checks after expanding Edits.
        """
        text = payload if isinstance(payload, str) else str(payload or "")
        path = (source_path or "").strip()
        if not path and source_args:
            for key in ("path", "file_path", "filename", "file"):
                v = source_args.get(key)
                if isinstance(v, str) and v.strip():
                    path = v.strip()
                    break
            if not path:
                cmd = str(source_args.get("command") or "")
                # head/cat/tail of a concrete file — bind that path for CSV/lines.
                import re as _re
                m = _re.search(
                    r"\b(?:head|cat|tail)\b[^\n]*?\s(/[^\s;|&]+|"
                    r"[A-Za-z0-9_./-]+\.csv)\b",
                    cmd,
                )
                if m:
                    path = m.group(1)
        if path and text.strip():
            # Strip Claude-style ``   12→`` line prefixes when present.
            import re as _re
            body = text
            if _re.search(r"(?m)^\s*\d+→", text):
                body = "\n".join(
                    _re.sub(r"^\s*\d+→", "", ln) for ln in text.splitlines()
                )
                self._file_text[path] = body
            # CSV header: wide comma row (head of .csv), not a numbered code line.
            header_src = text if "→" not in text.splitlines()[0] else body
            header_line = header_src.splitlines()[0].strip() if header_src.strip() else ""
            if (
                header_line
                and "," in header_line
                and not header_line[0].isdigit()
            ):
                cols = [
                    c.strip().strip('"').lower() for c in header_line.split(",")
                ]
                if len(cols) >= 2 and all(cols):
                    self._csv_columns[path] = cols
        # Conditional ceilings read FACTS, and a fact is only ever a structured
        # field of a tool output. Free text never becomes one: the guard
        # machinery is monotone-tightening precisely because this input may be
        # attacker-controlled, and the structured/free-text split is the same
        # distinction `ParameterProvenance` already draws about what counts as a
        # trustworthy origin. Feeding facts here rather than at a new entry point
        # is deliberate; `observe_context` was dead for exactly that reason.
        if structured_fields and self.conditional_tools is not None:
            try:
                self.conditional_tools.observe_facts(structured_fields)
            except Exception:  # noqa: BLE001, S110 - same reasoning as below
                pass
        if structured_fields:
            for budget in (self.value_budget, self.call_budget):
                config = getattr(budget, "config", None)
                observe = getattr(config, "observe_facts", None)
                if observe is not None:
                    try:
                        observe(structured_fields)
                    except Exception:  # noqa: BLE001, S110 - see below
                        # A malformed field must not take down the agent run from
                        # the OBSERVATION path, which grants no authority. And a
                        # fact that fails to land can only leave a ceiling
                        # LOOSER than intended by the tightening rule, so this is
                        # the one place where a swallowed error is not a
                        # fail-open: the base ceiling still applies.
                        pass
        if self.provenance is not None:
            self.provenance.record_observation(
                tool, payload,
                structured_fields=structured_fields,
                goal_named=goal_named,
                containing_object=containing_object,
            )
        if self.flow is not None and self.sensitivity is not None:
            # Same ingestion boundary as parameter provenance, deliberately: the
            # payload is already here, already has its source path, and adding a
            # second entry point is how `observe_context` ended up dead.
            try:
                self.flow.observe(
                    tool, containing_object or path or "", payload,
                    policy=self.sensitivity, path=path or None,
                    structured_fields=structured_fields,
                )
            except Exception:  # noqa: BLE001, S110 - observation is best-effort
                # `observe_output` is called by the integrator after a tool
                # returns, on arbitrary tool payloads. A tracker that raises on
                # an unexpected shape would take down the agent run from the
                # OBSERVATION path, which grants no authority at all. Missing an
                # observation only costs precision at the next decision.
                pass

    def _note_edit_locked(self, path: str, old: str, new: str) -> None:
        """Apply an Edit to session file text and accumulate line shift."""
        if not path:
            return
        old_n = old.count("\n") + (1 if old else 0)
        new_n = new.count("\n") + (1 if new else 0)
        delta = new_n - old_n
        if delta > 0:
            self._file_line_shift[path] = self._file_line_shift.get(path, 0) + delta
        cur = self._file_text.get(path)
        if cur is not None and old and old in cur:
            self._file_text[path] = cur.replace(old, new, 1)

    @property
    def _destination_bound(self) -> bool:
        """Is an active destination-binding floor standing behind this decision?

        Only true when an egress policy is configured, which is what makes
        ``defer_to_binding`` conditional rather than a blanket relaxation. With
        no egress policy the intent envelope is the only thing between an
        injected send and the attacker's address, and deferring would hand the
        attack through. With one, the destination has already been checked
        against the goal-derived trusted set before this point.
        """
        return self.egress is not None

    # -- floor ---------------------------------------------------------------
    def _floor(self, action: Action) -> tuple[bool, str, dict, bool]:
        # Returns (ok, reason, prevented, hard). `hard` distinguishes a denial
        # backed by POSITIVE evidence of malice (protected zone, unauthorized
        # write path, egress to an untrusted destination) from a SOFT scope miss
        # (a tool simply not in the goal-derived scope). Positive-evidence
        # denials hard-block; a scope miss steps up, because it is uncertainty,
        # not malice, and STEP_UP halts an attack just as hard while letting a
        # benign scope-missed effect be confirmed under supervision.
        # EXPIRY FIRST. A grant that has stopped authorizing authorizes nothing,
        # so this precedes every other check rather than sitting among them.
        #
        # This was enforced nowhere. Every mandate schema carries `expires_at`,
        # thirteen benchmark loaders write one, `compile_task_scope` discarded it,
        # and a grant that expired four hundred days ago allowed the action with
        # an empty reason list. An expiry nobody reads is not a control.
        #
        # Hard, not a step-up: an expired grant is not uncertainty about scope,
        # it is the absence of authority, and the answer is to get a new one.
        if self.scope is not None and self.scope.is_expired(self.clock()):
            return (False,
                    f"mandate {self.scope.mandate_id or ''} expired at "
                    f"{self.scope.expires_at}", {"expired": True}, True)
        # WHOSE authority, before what it points at. An action nobody signed for
        # is the confused deputy's best disguise, so an unattributed action in a
        # delegating session fails closed.
        if self.delegation is not None:
            principal = (action.meta or {}).get("principal")
            if principal is None:
                return (False, "action carries no acting principal",
                        {"delegation": True}, True)
            verdict = self.delegation.authorize(
                principal=principal, resource=action.resource,
                action=action.verb,
                envelope=self.delegation_envelopes.get(principal))
            if not verdict.allowed:
                return (False, f"{verdict.rule}: {verdict.reason}",
                        {"delegation": True}, True)
        # Tool / capability / arg-hash binding — same primitives as the ladder
        # engines, so scoreboard and SessionBroker share one floor.
        if self.tool_patterns is not None:
            import fnmatch
            if not any(fnmatch.fnmatch(action.tool, p) for p in self.tool_patterns):
                return False, f"tool {action.tool!r} not granted", {}, True
        elif self.allowed_tools is not None and action.tool not in self.allowed_tools:
            return False, f"tool {action.tool!r} not granted", {}, True
        if self.conditional_tools is not None and \
                action.tool in self.conditional_tools.withdrawn():
            return (False,
                    f"tool {action.tool!r} withdrawn: "
                    f"{self.conditional_tools.reason_for(action.tool)}",
                    {}, True)
        if self.capabilities:
            if not capability_allows(
                normalize_capabilities(self.capabilities),
                action.resource, action.verb,
            ):
                return (
                    False,
                    f"no capability for {action.resource}:{action.verb}",
                    {}, True,
                )
        if self.authorized_arg_hashes is not None:
            bound = self.authorized_arg_hashes.get(action.tool)
            if bound is not None:
                h = hash_canonical_json(action.args)
                if h not in bound:
                    # Match ladder TaskScopeInputBindingEngine: empty-arg READ
                    # of a bound tool is an unfiltered ask, not a redirect.
                    _read = frozenset(
                        {"read", "search", "list", "get", "query"}
                    )
                    if not action.args and action.verb in _read:
                        pass
                    else:
                        return (
                            False,
                            f"arguments for {action.tool!r} not in authorized set",
                            {}, True,
                        )
        path = _action_path(action)
        allow_exceptions = set(self.scope.allowed_paths) if self.scope else set()
        # HARD denials first: positive evidence of malice takes precedence over a
        # soft scope miss, so a scope-missed tool that also targets an attacker
        # destination is hard-denied by egress, not merely stepped up.
        if path and is_protected_path(path, allow_exceptions=allow_exceptions):
            return False, protected_reason(path) or "protected zone", {"protected_read": action.verb not in _WRITE_ACTIONS, "protected_write": action.verb in _WRITE_ACTIONS}, True
        if self.scope is not None and path is not None and not task_scope_allows_path(self.scope, path):
            return False, f"path {path!r} outside scope", {}, True
        # Destination binding runs on any action carrying an external
        # destination, not only effect verbs: a read of an attacker-controlled
        # URL (SSRF-style exfil) is an acquisition, so a verb gate would miss it.
        # egress.check is a no-op when the args carry no external destination.
        # Credential-shaped VALUES in the payload. No provenance in this
        # predicate at all, which is the point: `FlowTracker` correlates a
        # secret READ with a later write, and BPL's `integration-invoice-cover`
        # never reads one — the elevation tool is refused and the agent simply
        # types `API_KEY=sk-live-...` into an invoice attachment bound for an
        # allow-listed internal address. Allow-listed tool, allow-listed
        # recipient, nothing to derive from, every other layer satisfied.
        #
        # Measured on BPL's own benign corpus before being wired here: 0 of 761
        # benign string arguments flagged, 97.5% upper bound 0.5%. PII detection
        # is deliberately NOT included — its one false positive is a payroll
        # extract sent to the payroll mailbox, which is a question about the
        # destination rather than the content, and the egress recipient check
        # owns that half.
        if self.refuse_credential_payloads and is_consequential(action):
            from agentauth.capabilities.hardening.secret_content import (
                credential_findings,
            )

            for value in (action.args or {}).values():
                reasons = credential_findings(value, include_pii=False)
                if reasons:
                    return (False, f"payload carries a credential: {reasons[0]}",
                            {"secret_content": True}, True)
        if self.egress is not None:
            if self.provenance is not None:
                verdict, reason = self.egress.check_with_provenance(
                    action.resource, action.args,
                    provenance=self.provenance,
                    goal_named_objects=self.goal_named_objects or None,
                )
                if verdict == "deny":
                    # Ungrounded / foreign-object destination. Graduated mode
                    # still steps up the ambiguous case; otherwise hard-deny.
                    return False, reason, {"egress": True}, not self.graduated
                if verdict == "step_up":
                    # Grounded but not allow-listed: supervision, never autonomy.
                    # Soft so authorize() raises STEP_UP (attacker still halted).
                    return False, reason, {"egress": True}, False
            else:
                ok, reason = self.egress.check(action.resource, action.args)
                if not ok:
                    # Hard by default; graduated mode steps up the ambiguous
                    # unknown-destination case instead (halts the attacker the same
                    # in autonomous mode, recoverable for a benign send).
                    return False, reason, {"egress": True}, not self.graduated
        # SOFT scope miss last: a tool simply not in the goal-derived scope is
        # uncertainty, not malice, so it steps up rather than hard-denies.
        if self.scope is not None:
            if self.scope.allowed_actions and action.verb not in self.scope.allowed_actions:
                # A disallowed verb class (e.g. no sends permitted at all) is a
                # stronger signal than a single missing tool: hard-deny it.
                return False, f"action {action.verb!r} out of scope", {}, True
            if (self.scope.allowed_resources
                    and action.resource not in self.scope.allowed_resources
                    and (action.resource, verb_class(action.verb)) not in self._extended
                    and action.verb != "read"):
                # Read-permissive / effect-strict: containment scales with
                # reversibility. An acquisition to an out-of-scope resource is
                # reversible and still guarded above by protected-zones and
                # egress, so strict resource membership is reserved for the
                # irreversible effect verbs where harm actually lands. Hard-
                # denying benign reads here was the dominant clean-utility leak.
                #
                # Runtime replanning applies here as well as at the envelope.
                # The planner picks the tool scope up front, and on an
                # open-ended task it cannot know which tools the job will need:
                # AgentDyn shopping needed `verify_shopping_account` and
                # `cart_total`, and their absence from the scope was the entire
                # residual block set once plan conformance was fixed (7 of 7
                # remaining denials, all at this line).
                #
                # The trust basis is identical to the envelope case. The judge
                # sees the sealed goal, the tool catalog and the action shape,
                # so asking it here is the same question asked at a different
                # gate, and is equivalent to having computed a more generous
                # whitelist in the clean context up front. Every other floor
                # check has already run and still applies.
                #
                # Gated on `scope_is_advisory`, because this is only defensible
                # when the resource list was a planner guess. A mandate-derived
                # grant is an authorization and is never widened here.
                if self.plan_extender is not None and self.scope_is_advisory:
                    verdict = self.plan_extender.consider(action.tool, action.verb)
                    if verdict.extended:
                        # Session-local, and bounded by the same cap as the
                        # shapes. Two defects were fixed here at once.
                        #
                        # It used to append to `self.scope.allowed_resources`,
                        # which is the caller's own TaskScope object. That
                        # mutation outlived the broker, so authority granted by
                        # one session's replanning leaked into every other
                        # session sharing that scope instance.
                        #
                        # And `max_extensions` bounds SHAPES, so one cleared
                        # shape admitted unlimited distinct resources: a single
                        # "this goal may write" verdict let every write target
                        # in the catalog through. The extension set is now
                        # capped independently, and an admitted resource is
                        # remembered with the verb class it was admitted for, so
                        # it cannot be reused under a different one.
                        key = (action.resource, verb_class(action.verb))
                        if (key not in self._extended
                                and len(self._extended) >= self.max_scope_extensions):
                            return (False,
                                    f"resource {action.resource!r} out of scope; "
                                    f"scope already extended "
                                    f"{self.max_scope_extensions} times", {}, False)
                        self._extended.add(key)
                        self._record_triggers([f"scope extended: {verdict.reason}"])
                        return True, f"scope extended: {verdict.reason}", {}, True
                return False, f"resource {action.resource!r} out of scope", {}, False
        return True, "within floor", {}, True

    # -- public gate ---------------------------------------------------------
    def _authorize_locked(self, action: Action) -> BrokerDecision:
        start = time.perf_counter()
        is_write = action.verb in _WRITE_ACTIONS

        # Fail closed on a declaration the sealed goal does not entail. Runs
        # before the floor so a sabotaged plan never reaches side effects.
        if self._declaration_denials:
            return self._finalize(
                action, Outcome.DENY, "declaration", self._declaration_denials,
                None, is_write, start, blocked=True)

        ok, reason, prevented, hard = self._floor(action)
        if not ok:
            if hard:
                if prevented:
                    self._telemetry(self.metrics.record_prevented, **prevented)
                return self._finalize(action, Outcome.DENY, "floor", (reason,), None,
                                      is_write, start, blocked=True)
            # Soft scope miss (uncertainty, not positive malice): step up. Halts
            # an attack tool the same in autonomous mode; a benign scope-missed
            # effect is recoverable under supervision instead of a hard failure.
            request = build_step_up_request(
                request_id=str(uuid4()), query_id=self.goal.query_id,
                resource_ref=action.resource, operation=action.verb, violations=[reason])
            return self._finalize(action, Outcome.STEP_UP, "floor", (reason,), None,
                                  is_write, start, step_up=request, step_up_flag=True)

        # Soft entailment advisory on a committed plan: step up consequential
        # actions (halts autonomous sabotage) without fail-closed deny.
        if self._declaration_advisories and is_consequential(action):
            request = build_step_up_request(
                request_id=str(uuid4()), query_id=self.goal.query_id,
                resource_ref=action.resource, operation=action.verb,
                violations=list(self._declaration_advisories))
            return self._finalize(
                action, Outcome.STEP_UP, "declaration-entailment",
                self._declaration_advisories, None,
                is_write, start, step_up=request, step_up_flag=True)

        # Content derivation: does this write carry a value that came from a
        # sensitive read, however it was reshaped on the way out?
        #
        # STEP_UP and never DENY. `flow_window.md` measures both halves: on real
        # benign tau2 traffic the tracker now refuses 0 of 1,242 events, and the
        # two-write split it used to miss entirely (200/200 out) is fully closed
        # (0/200). But 22 fragments out of order still walk out in 162/200 runs,
        # and unkeyed encodings (base85, decimal byte codes) are 100/100 at every
        # width. Sound where it fires and incomplete in what it catches, which is
        # exactly the profile that should ask a human rather than refuse.
        #
        # Placed after the floor so a hard denial still wins, and before the
        # intent envelope so a derivation objection is raised on its own terms
        # rather than being absorbed into an off-plan verdict.
        if (
            self.flow is not None
            and self.sensitivity is not None
            and getattr(self.sensitivity, "active", False)
        ):
            try:
                verdict = self.flow.check(
                    tool=action.tool, verb=action.verb, resource=action.resource,
                    args=action.args, policy=self.sensitivity,
                    path=_action_path(action),
                )
            except Exception:  # noqa: BLE001 - a gate may deny, not crash
                verdict = None
            if verdict is not None and not verdict.allowed:
                reasons = (f"flow: {verdict.reason}",)
                request = build_step_up_request(
                    request_id=str(uuid4()), query_id=self.goal.query_id,
                    resource_ref=action.resource, operation=action.verb,
                    violations=list(reasons))
                return self._finalize(
                    action, Outcome.STEP_UP, "flow", reasons, None,
                    is_write, start, step_up=request, step_up_flag=True)

        # Execution vs accepted declaration (deployable corridor): argv / content
        # digest / callee / secret-flow drift → STEP_UP. Needs a prior
        # commit_plan; never consults a gifted clean twin.
        if (
            self._sealed_plan is not None
            and not self._declaration_denials
            and is_consequential(action)
        ):
            from agentauth.capabilities.monitor.sealed_plan import (
                check_sealed_plan,
                check_secret_flow,
            )

            sealed_reasons = [
                f"sealed-plan: {r}" for r in check_sealed_plan(action, self._sealed_plan)
            ]
            probe = Trajectory(
                goal=self.goal,
                actions=[*self._trajectory.actions, action],
            )
            sealed_reasons.extend(
                f"sealed-plan: {r}" for r in check_secret_flow(probe, self._sealed_plan)
            )
            if sealed_reasons:
                self._sealed_violation_taint = True
                request = build_step_up_request(
                    request_id=str(uuid4()), query_id=self.goal.query_id,
                    resource_ref=action.resource, operation=action.verb,
                    violations=sealed_reasons)
                return self._finalize(
                    action, Outcome.STEP_UP, "sealed-plan",
                    tuple(sealed_reasons), None,
                    is_write, start, step_up=request, step_up_flag=True)

            # Soft digΔ vs declaration body at the same dest (intent advisory).
            from agentauth.capabilities.monitor.intent_advisory import (
                assess_intent_advisory,
            )

            adv = assess_intent_advisory(
                probe,
                declaration=self.declared_plan,
                goal_text=self.goal.summary or "",
            )
            if adv.escalate:
                self._sealed_violation_taint = True
                request = build_step_up_request(
                    request_id=str(uuid4()), query_id=self.goal.query_id,
                    resource_ref=action.resource, operation=action.verb,
                    violations=list(adv.reasons))
                return self._finalize(
                    action, Outcome.STEP_UP, "intent-advisory",
                    tuple(adv.reasons), None,
                    is_write, start, step_up=request, step_up_flag=True)

        # Corpus-derived session rules (opt-in). Extracted to
        # `session_rules.py`: 160 lines of scenario-specific regex used to sit
        # here, invisible in the field list and unswitchable by a caller. Same
        # predicates, same reason strings, same order — now named, documented and
        # off unless asked for. See that module for what each rule is and is not.
        if self.session_rules:
            from agentauth.capabilities import session_rules as _rules

            _rules.observe(action, self.session)
            hit = _rules.check(
                action, self.session,
                goal_summary=self.goal.summary or "",
                egress_verbs=frozenset(_EGRESS_ACTIONS),
            )
            if hit is not None:
                request = build_step_up_request(
                    request_id=str(uuid4()), query_id=self.goal.query_id,
                    resource_ref=action.resource, operation=action.verb,
                    violations=[hit.reason])
                return self._finalize(
                    action, Outcome.STEP_UP, hit.layer, (hit.reason,), None,
                    is_write, start, step_up=request, step_up_flag=True)


        # Opt-in: undeclared *surprise* egress must commit_plan first (soft).
        # If the sealed goal already asks to email/post/upload, a blunt gate
        # invents soft FB on every legitimate send (measured ~18% on AgentHarm).
        if (
            self.require_declaration_for_egress
            and self.declared_plan is None
            and action.verb in _EGRESS_ACTIONS
        ):
            goal_l = (self.goal.summary or "").lower()
            egress_expected = any(
                w in goal_l
                for w in (
                    "email", "e-mail", "send", "post", "message", "upload",
                    "share", "tweet", "dm ", "slack", "webhook", "http",
                    "https", "curl", "publish",
                )
            )
            if not egress_expected:
                why = (
                    "declaration required before surprise egress "
                    "(goal does not request send/post/upload)"
                )
                request = build_step_up_request(
                    request_id=str(uuid4()), query_id=self.goal.query_id,
                    resource_ref=action.resource, operation=action.verb,
                    violations=[why])
                return self._finalize(
                    action, Outcome.STEP_UP, "declaration-required", (why,),
                    None, is_write, start, step_up=request, step_up_flag=True)

        # Online soft content check when nothing was declared: high-precision
        # deterministic patterns on this write body vs the sealed goal, then
        # optional LLM entailment (fail-open). Same STEP_UP contract; never hard-deny.
        if (
            not self._declaration_advisories
            and not self._declaration_denials
            and self._sealed_plan is None
            and is_consequential(action)
            and (self.goal.summary or "").strip()
        ):
            from agentauth.capabilities.monitor.action import path_hint
            from agentauth.capabilities.monitor.entailment import (
                deterministic_content_reasons,
            )
            from agentauth.capabilities.monitor.sealed_plan import _write_body

            # Full body (no head/tail cut): det patterns can live mid-file.
            # Also read prompt/body for AgentHarm-shaped free-text payloads.
            body = (
                _write_body(action)
                or str(action.args.get("content") or "")
                or str(action.args.get("new_string") or "")
                or str(action.args.get("command") or "")
                or str(action.args.get("prompt") or "")
                or str(action.args.get("body") or "")
            )
            if len(body.strip()) >= 40:
                dest = path_hint(action) or str(
                    action.args.get("file_path") or action.args.get("path") or "")
                sample = {"tool": action.tool, "dest": dest, "snippet": body}
                online = deterministic_content_reasons(
                    self.goal.summary or "", [sample],
                )
                if not online and self.entailment_judge is not None:
                    try:
                        # Truncate for cost; judge is fail-open on errors.
                        clipped = dict(sample)
                        clipped["snippet"] = body[:4000]
                        online = list(
                            self.entailment_judge(
                                self.goal.summary or "", [clipped])
                            or ()
                        )
                    except Exception:  # noqa: BLE001 - judge is fail-open by design
                        # The judge is a remote model. A timeout, a rate limit or
                        # a malformed completion must not decide an authorization,
                        # and this layer only ever produces STEP_UP, so failing
                        # open here forfeits an advisory rather than a control.
                        online = []
                if online:
                    request = build_step_up_request(
                        request_id=str(uuid4()), query_id=self.goal.query_id,
                        resource_ref=action.resource, operation=action.verb,
                        violations=list(online))
                    return self._finalize(
                        action, Outcome.STEP_UP, "content-entailment",
                        tuple(online), None,
                        is_write, start, step_up=request, step_up_flag=True)

        # Reserve budgets; a downstream behavioral block releases them.
        v_res = self.value_budget.reserve(action.tool, action.args) if self.value_budget else None
        c_res = self.call_budget.reserve(action.tool, action.args) if self.call_budget else None
        if (v_res is not None and not v_res.allowed) or (c_res is not None and not c_res.allowed):
            if v_res is not None and v_res.allowed:
                v_res.release()
            reason = (v_res.reason if v_res and not v_res.allowed else c_res.reason)  # type: ignore[union-attr]
            self._telemetry(self.metrics.record_prevented,
                            protected_write=is_write)
            return self._finalize(action, Outcome.DENY, "floor", (reason,), None,
                                  is_write, start, blocked=True)

        # Behavioral layer over the running trajectory.
        self._trajectory.actions.append(action)

        # Primary tier: goal-derived intent-envelope conformance (history-free).
        # Two-signal gate: an off-plan action is blocked only if it is also
        # consequential; otherwise it escalates for review.
        if self.intent_envelope is not None:
            # Provenance-typed slots (AuthGraph-shaped). A matching template with
            # TRUSTED_READ/GOAL constraints fails closed on consequential effects
            # when the value is ungrounded — independent of plan membership.
            slot = self.intent_envelope.check_slots(
                action,
                provenance=self.provenance,
                goal_text=self.goal.summary or "",
                goal_named_objects=self.goal_named_objects or None,
            )
            if slot is not None and is_consequential(action):
                self._rollback(action, v_res, c_res)
                self._record_triggers([f"intent-slot: {slot.reason}"])
                return self._finalize(
                    action, Outcome.DENY, "intent-envelope",
                    (slot.reason, "off-slot and consequential"), None,
                    is_write, start, blocked=True)

            dev = self.intent_envelope.last_deviation(self._trajectory)
            reason = None
            # Two distinct signals, and only one of them is a planner-recall
            # failure. A DEVIATION says the agent took a step the compiled plan
            # did not list, which on an open-ended task is usually the planner
            # failing to enumerate. INFEASIBILITY says the action steered the
            # mission out of reach, and no amount of shape plausibility restores
            # a goal condition that can no longer be met. Replanning may answer
            # the first and must not answer the second.
            replannable = False
            # A DERIVED count miss is not the same kind of evidence as an
            # off-plan tool. The bound came from reading the sealed goal, not
            # from anyone declaring it, so "you said one and this is the second"
            # is a reason to ask rather than a reason to refuse: a retry after a
            # failed send looks exactly like this. It steps up even when the
            # action is consequential, which is the one place the usual
            # off-plan-and-consequential denial does not apply.
            # `getattr` rather than attribute access: `intent_envelope` is a
            # pluggable seam and `last_deviation` returns whatever that
            # implementation returns. Reading a field off it unguarded made a
            # test double with a different shape raise from inside the
            # authorization path, which is the failure mode this file spends
            # most of its comments avoiding.
            derived_count_miss = (
                getattr(dev, "deviation", None) is Deviation.OVER_COUNT)
            if dev is not None:
                reason = dev.reason
                replannable = True
            else:
                ok, why = self.intent_envelope.feasible(self._trajectory)
                if not ok:
                    reason = why  # the action steered the mission out of reach
            if reason is not None:
                self._record_triggers([f"intent: {reason}"])
                # Runtime replanning, before any denial. An open-ended task
                # cannot state its steps in advance, and refusing every
                # unforeseen step is what produced zero utility on AgentDyn.
                #
                # The rollback that used to sit above this point is now below
                # it, and the ordering is load-bearing. Releasing the budget
                # reservations and popping the action off the trajectory before
                # asking the extender meant every extended action was free: the
                # value and call ledgers never incremented, so a cumulative
                # ceiling could never be reached however many actions were
                # extended, and the action was invisible to the trajectory
                # detector and to every later `feasible` and `last_deviation`
                # check. Replanning grows the PLAN and has no authority over
                # budgets; an extended action executed, so it pays.
                # A CONSEQUENTIAL off-plan action may only be replanned when the
                # binding floor positively validated where it points.
                #
                # MEASURED. Without this interlock, replanning is
                # `defer_allows_bound` under another name and fails the same way:
                # on AgentDojo travel it took ASR from 11.1% to 22.2% while
                # taking clean utility from 50.0% to 100.0%. The shape check is
                # not enough on its own, because a travel-booking goal plausibly
                # implies sending and booking, so the injected action is
                # shape-consistent and only the destination distinguishes it.
                #
                # The two checks are independent, which is the whole design: an
                # attacker needs both a shape the goal implies AND a destination
                # the floor accepts. Dropping either one gives the shape check
                # sole responsibility for containment, and it cannot carry it.
                extendable = replannable and (
                    not is_consequential(action)
                    or (self._destination_bound
                        and self.egress is not None
                        and self.egress.binds(action.resource, action.args))
                )
                if self.plan_extender is not None and extendable:
                    verdict = self.plan_extender.consider(action.tool, action.verb)
                    if verdict.extended:
                        # ATC re-clearance: grow the sealed envelope from the
                        # trusted shape judgment so later membership checks see
                        # the same plan. Never regenerates from tool output.
                        if self.intent_envelope is not None:
                            self.reclear(
                                self.intent_envelope.with_shape(
                                    action.tool, action.verb))
                        self._record_triggers([f"replan: {verdict.reason}"])
                        return self._commit_and_finalize(
                            action, v_res, c_res, "intent-envelope",
                            (reason, f"plan extended: {verdict.reason}"),
                            is_write, start)

                if is_consequential(action):
                    # A plan miss on an action the binding floor already cleared
                    # is the planner failing to enumerate, not the agent going
                    # rogue. Step up rather than deny: autonomous execution still
                    # halts, so an attacker gains nothing, and the benign case
                    # becomes recoverable instead of a hard loss.
                    if self.defer_to_binding and self._destination_bound:
                        # Two tiers, because the evidence comes in two strengths.
                        #
                        # If the floor positively VALIDATED a destination on this
                        # action, the strongest thing an attacker needs (an
                        # address of their own) has already been denied to them,
                        # and a plan miss is then almost certainly the planner
                        # failing to enumerate a legitimate step. Allow it.
                        #
                        # If the action carried no destination at all, the floor
                        # had no opinion on it. That is not evidence of anything,
                        # so it steps up rather than passing: still no hard loss,
                        # still no silent execution of something unvouched-for.
                        if (self.defer_allows_bound
                                and self.egress is not None
                                and self.egress.binds(action.resource, action.args)):
                            # Same rule as the replan path above: an allowed
                            # action pays its budget and stays on the trajectory.
                            return self._commit_and_finalize(
                                action, v_res, c_res, "intent-envelope",
                                (reason, "off-plan; destination validated by binding floor"),
                                is_write, start)
                        self._rollback(action, v_res, c_res)
                        request = build_step_up_request(
                            request_id=str(uuid4()), query_id=self.goal.query_id,
                            resource_ref=action.resource, operation=action.verb,
                            violations=[reason])
                        return self._finalize(
                            action, Outcome.STEP_UP, "intent-envelope",
                            (reason, "off-plan but destination-bound"), None,
                            is_write, start, step_up=request, step_up_flag=True)
                    if derived_count_miss:
                        self._rollback(action, v_res, c_res)
                        request = build_step_up_request(
                            request_id=str(uuid4()), query_id=self.goal.query_id,
                            resource_ref=action.resource, operation=action.verb,
                            violations=[reason])
                        return self._finalize(
                            action, Outcome.STEP_UP, "intent-envelope",
                            (reason, "count derived from the goal, not declared"),
                            None, is_write, start, step_up=request,
                            step_up_flag=True)
                    self._rollback(action, v_res, c_res)
                    return self._finalize(action, Outcome.DENY, "intent-envelope",
                                          (reason, "off-plan and consequential"), None,
                                          is_write, start, blocked=True)
                self._rollback(action, v_res, c_res)
                request = build_step_up_request(
                    request_id=str(uuid4()), query_id=self.goal.query_id,
                    resource_ref=action.resource, operation=action.verb, violations=[reason])
                return self._finalize(action, Outcome.STEP_UP, "intent-envelope", (reason,),
                                      None, is_write, start, step_up=request, step_up_flag=True)

        decision, reasons, score = self._behavioral()
        # Demote the statistical sensor: advisory mode never hard-blocks; otherwise
        # (with an envelope) the two-signal rule blocks only consequential actions.
        if decision is Outcome.DENY and (
                self.detector_advisory
                or (self.intent_envelope is not None and not is_consequential(action))):
            decision = Outcome.STEP_UP
            reasons = [*list(reasons), "demoted: advisory sensor flag"]

        if decision is Outcome.DENY:
            self._rollback(action, v_res, c_res)
            self._record_triggers(reasons)
            return self._finalize(action, Outcome.DENY, "behavioral", tuple(reasons), score,
                                  is_write, start, blocked=True)
        if decision is Outcome.STEP_UP:
            self._rollback(action, v_res, c_res)
            self._record_triggers(reasons)
            request = build_step_up_request(
                request_id=str(uuid4()), query_id=self.goal.query_id,
                resource_ref=action.resource, operation=action.verb, violations=list(reasons),
            )
            return self._finalize(action, Outcome.STEP_UP, "behavioral", tuple(reasons), score,
                                  is_write, start, step_up=request, step_up_flag=True)

        # Allow: commit reservations.
        return self._commit_and_finalize(action, v_res, c_res, "-", (),
                                         is_write, start, score=score)

    def _commit_and_finalize(self, action, v_res, c_res, layer, reasons,
                             is_write, start, *, score=None) -> BrokerDecision:
        """The only way to return ALLOW. Reservations become spend here.

        Every allow path has to go through this. The alternative, each site
        remembering to commit, is what produced the defect this replaces: the
        replan and `defer_allows_bound` paths returned ALLOW after a rollback
        had already released their reservations, so those actions executed
        against a ledger that never recorded them and a cumulative ceiling could
        never be reached.
        """
        # The gateway's own record that this tool ran, which is what an ordering
        # rule reads. Set HERE because this is the only way to return ALLOW, so
        # a tool that was refused never counts as having run. `record_call` is
        # separate from `observe_facts` on purpose: tool output may not write it.
        if self.conditional_tools is not None:
            try:
                self.conditional_tools.record_call(action.tool)
            except Exception:  # noqa: BLE001, S110 - bookkeeping never decides
                pass
        if v_res is not None and v_res.allowed:
            v_res.commit()
        if c_res is not None and c_res.allowed:
            c_res.commit()
        return self._finalize(action, Outcome.ALLOW, layer, reasons, score,
                              is_write, start)

    def _resolve_step_up_locked(self, approval) -> tuple[bool, str]:
        """Answer an outstanding STEP_UP and record the authority it granted.

        The missing half of the protocol. `step_up.py` has shipped a complete
        signed request/approval/verify chain since DP-30, and nothing ever called
        it: `apply_step_up` and `StepUpApproval` appear only in tests, and the
        broker had no entry point at all. So a STEP_UP was terminal, the request
        was attached to the decision and dropped, and **every "supervised
        utility" number in benchmarks/results/ is a counterfactual** that assumes
        a human said yes and that the task then succeeded.

        Order is deliberate:

        1. **Commitment must be one this session issued.** Checked first, before
           any crypto, so an approval for somebody else's request is rejected
           without spending verification on attacker-supplied bytes.
        2. **Signature**, via the existing `verify_step_up_approval`, which
           already binds the approval to the request commitment and so already
           refuses an approval replayed against a *different* request.
        3. **Single use**, by `approval_id`, so one approval clears one action
           rather than standing for the rest of the session.
        4. **Expiry**, against the request's own `expires_at`.

        The grant it writes is deliberately narrow: a one-shot keyed on
        ``(tool, arguments_hash)`` waiving only the rule codes the human was
        actually shown. An approval of a destination does not clear a budget
        ceiling nobody saw, and the same tool called with different arguments is
        a different question.

        Returns ``(resolved, reason)``. The caller re-authorizes the same action;
        it does not execute on the strength of this alone.
        """
        commitment = getattr(approval, "request_commitment", None) or (
            getattr(getattr(approval, "approval", None), "request_commitment", None))
        if not commitment:
            return False, "approval carries no request commitment"
        request = self._pending.get(commitment)
        if request is None:
            return False, "approval answers no request this session issued"

        try:
            ok, reason = verify_step_up_approval(approval, request_commitment=commitment)
        except Exception as exc:  # noqa: BLE001
            # Total by contract, like every other gate audited this session. The
            # approval object crosses a trust boundary, so a malformed one is a
            # denial with a reason, never an AttributeError out of the broker.
            return False, f"approval malformed: {type(exc).__name__}"
        if not ok:
            return False, f"approval rejected: {reason}"

        inner = getattr(approval, "approval", approval)
        approval_id = getattr(inner, "approval_id", None)
        if approval_id is None:
            return False, "approval carries no id"
        if approval_id in self._consumed:
            return False, "approval already used"

        if request.expires_at:
            try:
                deadline = datetime.fromisoformat(request.expires_at)
            except ValueError:
                return False, "request expiry unparseable"
            if deadline <= _utcnow():
                return False, "step-up request expired"

        codes = tuple(request.codes) or ("unclassified",)
        if "unclassified" in codes:
            # A rule with no id cannot be waived: nobody can say what was
            # approved. Fails closed on purpose, so adding a step-up path without
            # classifying it does not silently become approvable.
            return False, "request contains an unclassified rule; cannot be waived"

        self._consumed.add(approval_id)
        self._pending.pop(commitment, None)
        self.grants.grant_one_shot(
            tool=request.tool,
            arguments_hash=request.arguments_hash,
            waived_codes=codes,
            source=GrantSource.HUMAN,
            ttl_seconds=getattr(inner, "ttl_seconds", 600) or 600,
            approval_id=approval_id,
        )
        return True, f"resolved: waived {', '.join(codes)}"

    def _trusted_candidates(self) -> tuple[str, ...]:
        """Grounded values a blocked agent may retry with (re-audited).

        Allow-list recipients first: those can clear the floor autonomously.
        Provenance structured values follow: they earn STEP_UP at egress
        (supervision), not silent ALLOW, so an autonomous retry prefers the
        allow-list. Cap at 8, since these are hints rather than a dump.

        A hint is the least load-bearing thing this class produces, and fault
        injection found it able to crash a decision that had already been made:
        a raising provenance graph took a DENY and turned it into an exception.
        A failure here costs the agent a retry suggestion and nothing else.
        """
        out: list[str] = []
        seen: set[str] = set()
        if self.egress is not None:
            for r in sorted(getattr(self.egress, "allowed_recipients", None) or ()):
                if r and r not in seen:
                    seen.add(r)
                    out.append(r)
        if self.provenance is not None:
            try:
                candidates = self.provenance.trusted_candidates(
                    structured_only=True,
                    goal_named_objects=self.goal_named_objects or None,
                )
            except Exception:  # noqa: BLE001 - a hint never blocks a decision
                self.telemetry_failures += 1
                candidates = ()
            for c in candidates:
                if c not in seen:
                    seen.add(c)
                    out.append(c)
        return tuple(out[:8])

    def _finalize(self, action, outcome, layer, reasons, score, is_write, start, *,
                  blocked=False, step_up=None, step_up_flag=False) -> BrokerDecision:
        # Charge the audit budget here rather than at each step-up site, so every
        # path that asks a human is counted. There are four such sites today and
        # adding a fifth without charging it would silently reintroduce the
        # unlimited-attention assumption this is here to remove.
        if step_up_flag and self.audit_budget is not None:
            if self.audits_spent >= self.audit_budget:
                exhausted = f"audit budget exhausted ({self.audit_budget} step-ups)"
                if self.on_audit_exhausted == "allow":
                    # A fail-open, and labelled as one. This turns "the human ran
                    # out of attention" into ALLOW, which is the same shape as the
                    # planner's old allow-all: an undefended decision that pools
                    # into the ordinary allow count and is invisible downstream.
                    #
                    # Kept because it is a legitimate research configuration (the
                    # attention axis needs both ends of the policy), but it is
                    # gated and it is stamped. `layer` becomes "audit-exhausted"
                    # so no analysis can mistake it for a clean pass, and
                    # `allow_on_exhaust_acknowledged` must be set explicitly by a
                    # caller that means it.
                    if not self.allow_on_exhaust_acknowledged:
                        outcome, blocked = Outcome.DENY, True
                        reasons = (*reasons, exhausted,
                                   "denied: allow-on-exhaust not acknowledged")
                    else:
                        outcome, layer = Outcome.ALLOW, "audit-exhausted"
                        reasons = (*reasons, exhausted,
                                   "allowed: budget policy is allow-on-exhaust")
                else:
                    outcome, blocked = Outcome.DENY, True
                    reasons = (*reasons, exhausted, "denied: no attention left to ask for")
                step_up, step_up_flag = None, False
            else:
                self.audits_spent += 1
        candidates: tuple[str, ...] = ()
        if outcome in (Outcome.DENY, Outcome.STEP_UP):
            candidates = self._trusted_candidates()
            if candidates and step_up is not None:
                # Surface retry hints on the step-up card without widening authority.
                suggested = dict(step_up.suggested_approval)
                suggested["trusted_candidates"] = list(candidates)
                # `replace`, not a field-by-field rebuild: the enumerated form
                # silently drops every field added to StepUpRequest afterwards,
                # which is how the action binding would have been lost here.
                step_up = _dc_replace(step_up, suggested_approval=suggested)
        if step_up is not None:
            # Bind the concrete action into the commitment here rather than at
            # each of the nine construction sites, so a new step-up path cannot
            # forget to. Then register it: `resolve_step_up` refuses any approval
            # whose commitment this session never issued, which is checked before
            # any signature work.
            step_up = bind_to_action(
                step_up,
                tool=action.tool,
                arguments_hash=hash_canonical_json(action.args),
                layer=layer,
                ttl_seconds=self.step_up_ttl_seconds,
            )
            if step_up_flag:
                self._pending[step_up.commitment()] = step_up
        # Everything below this line is bookkeeping: the decision is already
        # made. Fault injection found that a failure in any of it took the whole
        # gateway down, so a metrics backend or an audit sink going away turned
        # into a total outage of authorization. A telemetry call is not allowed
        # to be load-bearing, and an audit write that fails must not discard a
        # decision that was correctly reached.
        #
        # None of it is swallowed. `unrecorded_decisions` counts every decision
        # the evidence plane cannot account for, which is the number a
        # deployment alerts on, in the same spirit as `DecisionLog.durability`
        # reporting what was evicted without reaching a sink.
        self._telemetry(self.metrics.record_action, blocked=blocked,
                        step_up=step_up_flag, is_write=is_write,
                        overhead_ms=(time.perf_counter() - start) * 1000)

        record = None
        try:
            record = self.decision_log.append(
                query_id=self.goal.query_id, tool=action.tool,
                resource=action.resource, action_verb=action.verb,
                arguments_hash=hash_canonical_json(action.args),
                outcome=outcome.value, layer=layer, reasons=tuple(reasons),
                anomaly_score=score,
                trace=self.trace.to_dict() if self.trace is not None else None,
            ).to_dict()
        except Exception:  # noqa: BLE001 - an unrecorded decision, not a lost one
            self.unrecorded_decisions += 1
        if record is not None and self.receipt_sink is not None:
            try:
                self.receipt_sink(record)
            except Exception:  # noqa: BLE001 - a sink is downstream of the decision
                self.unrecorded_decisions += 1
        return BrokerDecision(
            outcome, layer, tuple(reasons), step_up=step_up, record=record,
            trusted_candidates=candidates,
        )

    # -- helpers -------------------------------------------------------------
    def _behavioral(self) -> tuple[Outcome, list[str], float | None]:
        if self.detector is None:
            return Outcome.ALLOW, [], None
        report = self.detector.assess(self._trajectory,
                                      reference=self.declared_plan)
        score = report.anomaly_p
        if report.blocked:
            reasons = list(report.structural_reasons) or [
                f"step {v.step} blocked" for v in report.verdicts if v.decision is Decision.BLOCK
            ]
            return Outcome.DENY, reasons, score
        escalate = [v for v in report.verdicts if v.decision is Decision.ESCALATE]
        if escalate and self.escalate_on_soft:
            return (Outcome.STEP_UP,
                    [r for v in escalate for r in v.reasons] or ["structural escalation"],
                    score)
        return Outcome.ALLOW, [], score

    def _rollback(self, action: Action, v_res, c_res) -> None:
        # The action did not execute: drop it from the trajectory and release budget.
        if self._trajectory.actions and self._trajectory.actions[-1] is action:
            self._trajectory.actions.pop()
        if v_res is not None and v_res.allowed:
            v_res.release()
        if c_res is not None and c_res.allowed:
            c_res.release()

    @property
    def _extended(self) -> set:
        """(resource, verb class) pairs replanning admitted, for THIS session.

        Session-local by construction. The previous version appended to
        `self.scope.allowed_resources`, which is the caller's own TaskScope
        object, so authority granted by one session's replanning outlived the
        broker and leaked into every other session sharing that instance.
        """
        if getattr(self, "_extended_pairs", None) is None:
            self._extended_pairs = set()
        return self._extended_pairs

    def _telemetry(self, call, /, **kwargs) -> None:
        """Record a metric, and never let recording one change a decision.

        Every telemetry call in this class goes through here. Fault injection
        found two that took the whole gateway down when the metrics object
        raised, and a third that only survived because the probe's own verdict
        rule was too lenient to notice. A counter is the right shape for what a
        deployment does about it: alert, not fail.
        """
        try:
            call(**kwargs)
        except Exception:  # noqa: BLE001 - telemetry is never load-bearing
            self.telemetry_failures += 1

    def _record_triggers(self, reasons: list[str]) -> None:
        joined = " ".join(reasons).lower()
        self._telemetry(
            self.metrics.record_monitor_trigger,
            scan=any(t in joined for t in ("path-envelope", "aml", "burst", "fan-out", "structuring")),
            drift="cusum" in joined or "drift" in joined,
            novelty="surprise" in joined or "novel" in joined,
        )
