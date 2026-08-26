"""One deployable SessionBroker profile shared by every benchmark path.

**One system contract.** Scoreboard product rows, CTR shared-stack arms,
``benchmarks.cli --mode stack``, ``cross_stack``, and live AgentDojo all build
the gateway through this factory. Ladder engines in ``build_engines()`` remain
a monotone *ablation* (floor construction), not a second product. Soft STEP_UP
and hard DENY stay separate metrics — never fold soft into a hard-ASR cell.

Profile (``DeployableStack``)
-----------------------------
1. Floor: tool grant, capabilities, path/resource scope, protected zones,
   commit-token argument binding, egress (± provenance when configured)
2. Declaration: ``commit_plan`` when a declared trajectory is supplied
   (hard deny on goal/content check failures; compiles sealed-plan constraints)
3. Soft content: plan entailment + sealed-plan/digΔ vs declaration + online
   ``deterministic_content_reasons`` on consequential writes (STEP_UP)
4. Session memory: CSV bind, line maps, packaging/sealed-violation taints
   (``SessionMemory`` — same object shape live and replay), evaluated by the
   ``session_rules`` pack. ON by default here because every published number was
   measured with it on; it is corpus-derived and STEP_UP-only, and a deployment
   on unlike traffic should measure with ``session_rules=False`` too. See
   ``agentauth/capabilities/session_rules.py``.
5. Parameter provenance (default on): containing-object sources for destinations
6. Runtime replan when an intent envelope is present: ``catalog_shape_judge``
   (trusted goal+catalog only) or caller-supplied LLM judge — never tool output
7. Optional LLM entailment judge (fail-open if no credentials)
8. Optional trajectory detector (advisory by default); ``reclear`` for mid-session
   envelope refresh on trusted input

Live AgentDojo sets ``scope_is_advisory=True`` and may attach provenance /
intent envelopes; deterministic corpora use mandate-rigid scope.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from agentauth.capabilities.broker import Outcome, SessionBroker
from agentauth.capabilities.mandate_lint import (
    lint_mandate,
    require_clean,
)
from agentauth.capabilities.monitor.action import Action, Trajectory
from agentauth.capabilities.monitor.llm_clients import default_entailment_judge
from agentauth.capabilities.parameter_provenance import ParameterProvenance
from agentauth.capabilities.scoping.goal import GoalSpec

# Sentinel: "create a fresh ParameterProvenance" (distinct from explicit None).
_PROVENANCE_DEFAULT = object()


def _goal_named_objects(goal: GoalSpec, extra: Iterable[str] | None = None) -> set[str]:
    """Paths / channel-like literals from the sealed goal (provenance roots)."""
    named: set[str] = set(extra or ())
    summary = goal.summary or ""
    for m in re.finditer(r"(?:/[\w./-]+|[\w.-]+\.(?:json|csv|txt|yaml|yml|md))\b", summary):
        named.add(m.group(0))
    for m in re.finditer(r"(?:channel|file|inbox|payees?|contacts?)[:\s]+([A-Za-z0-9_./-]+)",
                         summary, re.IGNORECASE):
        named.add(m.group(1))
    for obj in (goal.structured_intent or {}).get("named_objects") or ():
        if isinstance(obj, str) and obj.strip():
            named.add(obj.strip())
    return named


def _replay_clock(scope) -> Callable[[], datetime] | None:
    """Pin UTC clock inside the mandate window for corpus replay.

    Fixture mandates carry fixed ``expires_at`` dates. Wall-clock expiry would
    turn every MCP/ASB replay into a false block once that date passes — the
    ladder never checked expiry, so the shared stack must pin a valid moment
    for fair cross-benchmark measurement. Live deployments keep wall clock.
    """
    if scope is None or scope.expires_at is None:
        return None
    exp = scope.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    pinned = exp - timedelta(seconds=1)

    def _now() -> datetime:
        return pinned

    return _now


@dataclass(frozen=True)
class StackDecision:
    """Normalized decision for benchmark scoring."""
    allowed: bool
    outcome: str
    layer: str
    reasons: tuple[str, ...]
    trusted_candidates: tuple[str, ...] = ()

    @classmethod
    def from_broker(cls, d) -> StackDecision:
        # Autonomous containment: STEP_UP halts the action the same as DENY.
        return cls(
            allowed=d.outcome is Outcome.ALLOW,
            outcome=d.outcome.value,
            layer=d.layer,
            reasons=tuple(d.reasons),
            trusted_candidates=tuple(getattr(d, "trusted_candidates", ()) or ()),
        )


def _lint_stack_mandate(*, value_budget, call_budget, allowed_tools,
                        declared_harmless=()):
    """Coverage findings for the budgets this stack was built with.

    Reads the configs off whatever budget objects were passed rather than
    requiring the caller to restate them, so the check cannot drift from what is
    actually enforced. Total: a stack must not fail to construct because its
    coverage check tripped over an unfamiliar budget object.

    `declared_harmless` is the operator's assertion that a tool has no effect
    worth counting. It used to be missing here while `lint_mandate` accepted it,
    so a policy document could declare a tool harmless, pass `clayseal policy
    lint` clean, and then have the gateway refuse to build on the finding the
    declaration was meant to answer. The linter and the gate now read the same
    input.
    """
    def _cfg(budget, attr):
        cfg = getattr(budget, "config", None)
        return dict(getattr(cfg, attr, None) or {})

    try:
        return lint_mandate(
            catalog=sorted(allowed_tools or ()),
            declared_harmless=sorted(declared_harmless or ()),
            value_tracked=_cfg(value_budget, "tracked"),
            call_tracked=_cfg(call_budget, "tracked"),
            ceilings={**_cfg(value_budget, "ceilings"),
                      **_cfg(call_budget, "ceilings")},
            # Session-scoped is the truth for these budget objects; a deployment
            # using `principal_ledger` is what silences that warning.
            principal_scoped=False,
        )
    except Exception:  # noqa: BLE001 - advisory check, never a construction gate
        return []



@dataclass
class DeployableStack:
    """Configured SessionBroker + helpers for replay / live."""

    broker: SessionBroker
    profile: str = "deployable"
    _last_broker_decision: Any = field(default=None, init=False, repr=False)
    #: Advisory mandate-coverage findings from , populated by
    #: . Empty on a directly-constructed stack.
    mandate_findings: list = field(default_factory=list, init=False, repr=False)

    @classmethod
    def from_goal(
        cls,
        goal: GoalSpec,
        *,
        scope=None,
        allowed_tools: set[str] | None = None,
        conditional_tools: Any = None,
        # Tools the operator asserts have no countable effect. Read only by the
        # mandate coverage check; it never widens what the floor allows.
        declared_harmless: set[str] | None = None,
        tool_patterns: list[str] | None = None,
        capabilities: list[dict[str, str]] | None = None,
        authorized_arg_hashes: dict[str, set[str]] | None = None,
        declared_plan: Trajectory | None = None,
        egress=None,
        provenance: Any = _PROVENANCE_DEFAULT,
        goal_named_objects: set[str] | None = None,
        intent_envelope=None,
        detector=None,
        entailment_judge: Any | None = ...,
        scope_is_advisory: bool = False,
        value_budget=None,
        call_budget=None,
        graduated: bool = False,
        defer_to_binding: bool = False,
        defer_allows_bound: bool = False,
        audit_budget: int | None = None,
        plan_extender=None,
        clock: Callable[[], Any] | None = None,
        replay_pin_clock: bool = False,
        require_declaration_for_egress: bool = False,
        enable_replan: bool = True,
        sensitivity=None,
        enable_flow: bool = True,
        strict_mandate: bool = False,
        session_rules: bool = True,
        receipt_sink: Any = ...,
    ) -> DeployableStack:
        if entailment_judge is ...:
            entailment_judge = default_entailment_judge()
        if receipt_sink is ...:
            # Never `None`. "No durable evidence" and "evidence configured and
            # working" must not look the same at runtime, so an unconfigured
            # deployment gets a sink that COUNTS what it drops rather than a
            # silent no-op. See `decision_sinks`.
            from agentauth.capabilities.decision_sinks import sink_from_env

            receipt_sink = sink_from_env()
        if clock is None and replay_pin_clock:
            clock = _replay_clock(scope)
        if provenance is _PROVENANCE_DEFAULT:
            provenance = ParameterProvenance()
        named = _goal_named_objects(goal, goal_named_objects)

        # Confidentiality flow. The mandate's own declaration wins; when it
        # declares nothing we fall back to the static secret taxonomy, which is
        # the clause `hardening/object_class.py` already states as its reason for
        # existing: "the defaults exist so that a mandate which does not
        # enumerate its own secrets is not silently unprotected."
        #
        # A repository contains its own credentials (.env, .npmrc, .git/config)
        # and its own publication surfaces, and a path scope cannot help with
        # either because the agent is legitimately granted the workspace that
        # holds them. That is the in-scope staging class, measured in
        # `benchmarks/results/in_scope_exfiltration.md` as a full-ladder escape
        # set byte-identical to allow-all.
        #
        # The layer is STEP_UP only, never DENY. See broker.flow and
        # `benchmarks/results/flow_window.md` for the measurement behind that.
        flow = None
        if enable_flow:
            from agentauth.capabilities.confidentiality import FlowTracker, SensitivityPolicy

            if sensitivity is None:
                declared = SensitivityPolicy.from_mandate(
                    getattr(scope, "mandate", None)
                    or (scope if isinstance(scope, dict) else None))
                if declared.active:
                    sensitivity = declared
                else:
                    from agentauth.capabilities.hardening.object_class import SECRET_PATTERNS

                    sensitivity = SensitivityPolicy(
                        sensitive=tuple(f"*{m}*" for m in SECRET_PATTERNS),
                        declassified_sinks=tuple(sorted(named)),
                    )
            if getattr(sensitivity, "active", False):
                flow = FlowTracker()

        # Default replan: catalog+goal shape judge when an envelope is present
        # and the caller did not supply an extender. Trusted input only.
        if (
            enable_replan
            and plan_extender is None
            and intent_envelope is not None
        ):
            from agentauth.capabilities.replan import PlanExtender, catalog_shape_judge
            from agentauth.capabilities.replan import verb_class as _verb_class

            catalog = sorted(allowed_tools or ())
            if not catalog and capabilities:
                catalog = sorted({
                    str(c.get("resource") or c.get("tool") or "")
                    for c in capabilities
                    if isinstance(c, dict)
                } - {""})
            allowed_classes = {
                _verb_class(a)
                for a in (scope.allowed_actions if scope is not None else ())
            } if scope is not None else set()
            # Also admit verbs from structured intent when present.
            for v in (goal.structured_intent or {}).get("verbs") or ():
                allowed_classes.add(_verb_class(str(v)))
            if catalog:
                plan_extender = PlanExtender(
                    judge=catalog_shape_judge(allowed_classes=allowed_classes),
                    goal=goal.summary or "",
                    catalog=catalog,
                )

        kwargs: dict[str, Any] = {
            "goal": goal,
            "scope": scope,
            "allowed_tools": allowed_tools,
            "conditional_tools": conditional_tools,
            "tool_patterns": tool_patterns,
            "capabilities": capabilities,
            "authorized_arg_hashes": authorized_arg_hashes,
            "declared_plan": declared_plan,
            "egress": egress,
            "provenance": provenance,
            "flow": flow,
            "sensitivity": sensitivity if flow is not None else None,
            "goal_named_objects": named,
            "intent_envelope": intent_envelope,
            "detector": detector,
            "detector_advisory": True,
            "entailment_judge": entailment_judge,
            "scope_is_advisory": scope_is_advisory,
            "value_budget": value_budget,
            "call_budget": call_budget,
            "graduated": graduated,
            "defer_to_binding": defer_to_binding,
            "defer_allows_bound": defer_allows_bound,
            "audit_budget": audit_budget,
            "plan_extender": plan_extender,
            "require_declaration_for_egress": require_declaration_for_egress,
            "session_rules": session_rules,
            "receipt_sink": receipt_sink,
        }
        if clock is not None:
            kwargs["clock"] = clock

        # Mandate coverage. `stress_aggregation.py` found five aggregation-key
        # escapes that are not defects in the ledger — it debited exactly what it
        # was told to, correctly, on every one — but in the mandate failing to
        # say what should be counted. A linter nobody calls does not close those,
        # so it runs here, on the path every deployment goes through.
        #
        # Advisory by default, and deliberately: `require_clean` turns an
        # uncovered money tool into a startup failure, which is right for a
        # production deployment and wrong for the benchmark harnesses that build
        # intentionally incomplete mandates to measure the escape. Callers opt in
        # via `strict_mandate=True`.
        stack = cls(broker=SessionBroker(**kwargs))
        stack.mandate_findings = _lint_stack_mandate(
            value_budget=value_budget, call_budget=call_budget,
            allowed_tools=allowed_tools, declared_harmless=declared_harmless)
        if strict_mandate:
            require_clean(stack.mandate_findings)
        return stack

    def authorize(self, action: Action) -> StackDecision:
        raw = self.broker.authorize(action)
        self._last_broker_decision = raw
        return StackDecision.from_broker(raw)

    def authorize_all(self, actions: Iterable[Action]) -> list[StackDecision]:
        return [self.authorize(a) for a in actions]

    def observe_context(self, item) -> None:
        """Tell the gateway about content the agent read.

        This is how the taint layer learns that an action's destination came
        from a document rather than from the sealed goal, so it is not optional
        detail: without it every destination looks equally well-sourced. It was
        missing from this class while `observe_output` was present, which meant
        the documented entry point could not report the one input the
        content-provenance tier is built on.
        """
        self.broker.observe_context(item)

    def observe_output(self, *args, **kwargs) -> None:
        """Forward tool results into session memory + parameter provenance."""
        self.broker.observe_output(*args, **kwargs)

    def resolve_step_up(self, approval) -> tuple[bool, str]:
        """Apply a signed human approval to a held action."""
        return self.broker.resolve_step_up(approval)

    @property
    def decision_log(self):
        """The hash-chained record of every decision this session made."""
        return self.broker.decision_log

    @property
    def metrics(self):
        """Prevented violations, monitor triggers, gateway overhead."""
        return self.broker.metrics

    def note_edit(self, path: str, old: str, new: str) -> None:
        self.broker.note_edit(path, old, new)

    def reclear(self, *args, **kwargs) -> bool:
        """Mid-session envelope refresh (trusted input only)."""
        return self.broker.reclear(*args, **kwargs)

    def commit_plan(self, plan: Trajectory) -> list[str]:
        return self.broker.commit_plan(plan)

    @property
    def session(self):
        return self.broker.session

    def declaration_denied(self) -> bool:
        return bool(self.broker._declaration_denials)

    def declaration_reasons(self) -> tuple[str, ...]:
        return tuple(self.broker._declaration_denials)

    def last_trusted_candidates(self) -> tuple[str, ...]:
        """Retry hints from the most recent floor DENY/STEP_UP (utility path)."""
        d = self._last_broker_decision
        if d is None:
            return ()
        return tuple(getattr(d, "trusted_candidates", ()) or ())
