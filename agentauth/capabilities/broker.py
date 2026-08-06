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

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from uuid import uuid4

from agentauth.core.hash_util import hash_canonical_json
from agentauth.core.task_scope import TaskScope, task_scope_allows_path
from agentauth.capabilities.decision_log import DecisionLog
from agentauth.capabilities.call_budget import SessionCallBudget
from agentauth.capabilities.hardening.egress_policy import EgressPolicy
from agentauth.capabilities.hardening.protected_zones import is_protected_path, protected_reason
from agentauth.capabilities.monitor import (
    Action,
    ContextItem,
    Decision,
    IntentEnvelope,
    TrajectoryDetector,
    Trajectory,
    is_consequential,
)
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.capabilities.scoping.metrics import ScopingMetrics
from agentauth.capabilities.step_up import StepUpRequest, build_step_up_request
from agentauth.capabilities.value_budget import SessionValueBudget


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

    @property
    def allowed(self) -> bool:
        return self.outcome is Outcome.ALLOW


_WRITE_ACTIONS = {"write", "create", "update", "delete", "send", "transfer", "post", "pay"}
_EGRESS_ACTIONS = {"send", "post", "transfer", "share"}


def _action_path(action: Action) -> str | None:
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
    metrics: ScopingMetrics = field(default_factory=ScopingMetrics)
    decision_log: DecisionLog = field(default_factory=DecisionLog)
    receipt_sink: Callable[[dict[str, Any]], None] | None = None
    _trajectory: Trajectory = field(init=False)

    def __post_init__(self) -> None:
        self._trajectory = Trajectory(goal=self.goal, actions=[], context=[])
        self.metrics.goal_id = self.goal.query_id

    # -- re-clearance (ATC) --------------------------------------------------
    def reclear(self, envelope: IntentEnvelope | None = None, *,
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
    def observe_context(self, item: ContextItem) -> None:
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
        if self.egress is not None:
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
                    and action.verb != "read"):
                # Read-permissive / effect-strict: containment scales with
                # reversibility. An acquisition to an out-of-scope resource is
                # reversible and still guarded above by protected-zones and
                # egress, so strict resource membership is reserved for the
                # irreversible effect verbs where harm actually lands. Hard-
                # denying benign reads here was the dominant clean-utility leak.
                return False, f"resource {action.resource!r} out of scope", {}, False
        return True, "within floor", {}, True

    # -- public gate ---------------------------------------------------------
    def authorize(self, action: Action) -> BrokerDecision:
        start = time.perf_counter()
        is_write = action.verb in _WRITE_ACTIONS

        ok, reason, prevented, hard = self._floor(action)
        if not ok:
            if hard:
                if prevented:
                    self.metrics.record_prevented(**prevented)
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

        # Reserve budgets; a downstream behavioral block releases them.
        v_res = self.value_budget.reserve(action.tool, action.args) if self.value_budget else None
        c_res = self.call_budget.reserve(action.tool, action.args) if self.call_budget else None
        if (v_res is not None and not v_res.allowed) or (c_res is not None and not c_res.allowed):
            if v_res is not None and v_res.allowed:
                v_res.release()
            reason = (v_res.reason if v_res and not v_res.allowed else c_res.reason)  # type: ignore[union-attr]
            self.metrics.record_prevented(protected_write=is_write)
            return self._finalize(action, Outcome.DENY, "floor", (reason,), None,
                                  is_write, start, blocked=True)

        # Behavioral layer over the running trajectory.
        self._trajectory.actions.append(action)

        # Primary tier: goal-derived intent-envelope conformance (history-free).
        # Two-signal gate: an off-plan action is blocked only if it is also
        # consequential; otherwise it escalates for review.
        if self.intent_envelope is not None:
            dev = self.intent_envelope.last_deviation(self._trajectory)
            reason = None
            if dev is not None:
                reason = dev.reason
            else:
                ok, why = self.intent_envelope.feasible(self._trajectory)
                if not ok:
                    reason = why  # the action steered the mission out of reach
            if reason is not None:
                self._rollback(action, v_res, c_res)
                self._record_triggers([f"intent: {reason}"])
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
                            return self._finalize(
                                action, Outcome.ALLOW, "intent-envelope",
                                (reason, "off-plan; destination validated by binding floor"),
                                None, is_write, start)
                        request = build_step_up_request(
                            request_id=str(uuid4()), query_id=self.goal.query_id,
                            resource_ref=action.resource, operation=action.verb,
                            violations=[reason])
                        return self._finalize(
                            action, Outcome.STEP_UP, "intent-envelope",
                            (reason, "off-plan but destination-bound"), None,
                            is_write, start, step_up=request, step_up_flag=True)
                    return self._finalize(action, Outcome.DENY, "intent-envelope",
                                          (reason, "off-plan and consequential"), None,
                                          is_write, start, blocked=True)
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
            reasons = list(reasons) + ["demoted: advisory sensor flag"]

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
        if v_res is not None:
            v_res.commit()
        if c_res is not None:
            c_res.commit()
        return self._finalize(action, Outcome.ALLOW, "-", (), score, is_write, start)

    def _finalize(self, action, outcome, layer, reasons, score, is_write, start, *,
                  blocked=False, step_up=None, step_up_flag=False) -> BrokerDecision:
        self.metrics.record_action(blocked=blocked, step_up=step_up_flag, is_write=is_write,
                                   overhead_ms=(time.perf_counter() - start) * 1000)
        record = self.decision_log.append(
            query_id=self.goal.query_id, tool=action.tool, resource=action.resource,
            action_verb=action.verb, arguments_hash=hash_canonical_json(action.args),
            outcome=outcome.value, layer=layer, reasons=tuple(reasons), anomaly_score=score,
        ).to_dict()
        if self.receipt_sink is not None:
            self.receipt_sink(record)
        return BrokerDecision(outcome, layer, tuple(reasons), step_up=step_up, record=record)

    # -- helpers -------------------------------------------------------------
    def _behavioral(self) -> tuple[Outcome, list[str], float | None]:
        if self.detector is None:
            return Outcome.ALLOW, [], None
        report = self.detector.assess(self._trajectory)
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

    def _record_triggers(self, reasons: list[str]) -> None:
        joined = " ".join(reasons).lower()
        self.metrics.record_monitor_trigger(
            scan=any(t in joined for t in ("path-envelope", "aml", "burst", "fan-out", "structuring")),
            drift="cusum" in joined or "drift" in joined,
            novelty="surprise" in joined or "novel" in joined,
        )
