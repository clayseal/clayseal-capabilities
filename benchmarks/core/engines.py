"""Decision engines: the *architectural approaches* under comparison.

Each engine wraps a REAL Clay Seal decision primitive (no reimplemented policy
logic) so the benchmark measures the shipping system, not a mock. Two families:

Enforcement ladder — increasing authority granularity on the same trace. Each
rung should contain strictly more attacks than the one below without adding
false blocks:

  allow-all            no enforcement (attack-prevention floor)
  tool-allowlist       naive RBAC: any call to an allowed tool name
  capability-token     resource:action match  (core.operations.capability_allows)
  task-scope           + path scoping          (core.task_scope.task_scope_allows_path)
  task-scope+binding   + argument binding      (commit-token arguments_hash)
  deny-all             blocks everything (friction ceiling)

Engine-integration family — the SAME compiled policy carried across pluggable
external authorization engines via ``agentauth.capabilities.authorizers``. Holds
policy fixed to expose per-engine decision parity and overhead, answering "which
authz engine should we integrate?" rather than "which scoping strategy wins?".
"""
from __future__ import annotations

import math
import random
from typing import Protocol, runtime_checkable

from agentauth.core.hash_util import hash_canonical_json
from agentauth.core.operations import capability_allows, normalize_capabilities
from agentauth.capabilities.hardening.protected_zones import is_protected_path, protected_reason
from agentauth.core.task_scope import (
    TaskScope,
    compile_task_scope,
    task_scope_allows_path,
)

from agentauth.capabilities.authorizers import (
    cedar_authorizer,
    opa_authorizer,
    openfga_authorizer,
)
from agentauth.capabilities.call_budget import session_call_budget_from_mandate
from agentauth.capabilities.value_budget import session_value_budget_from_mandate

from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, Decision, EventLabel


# Verbs that change external state. Deliberately wider than runner._WRITE_ACTIONS,
# which classifies protected *writes* for metrics: an `execute` or a `send` is an
# effect for authorization purposes even where it is not a filesystem write.
_EFFECT_ACTIONS = frozenset({
    "write", "create", "update", "delete", "send", "transfer", "post", "pay", "execute",
})

# Verbs that acquire without changing anything. Named positively, because the
# complement of _EFFECT_ACTIONS is not the same set: `classify_verb` falls back
# to `call` for any verb it does not recognise, and `call` is not an effect, so
# a rule written for reads and expressed as "not an effect" silently covers
# every unclassified consequential tool.
_READ_ACTIONS = frozenset({"read", "search", "list", "get", "query"})


@runtime_checkable
class DecisionEngine(Protocol):
    name: str

    def decide(self, task: BenchmarkTask, event: BenchmarkEvent) -> Decision:  # pragma: no cover - protocol
        ...


# --------------------------------------------------------------------------- #
# Enforcement ladder
# --------------------------------------------------------------------------- #
class AllowAllEngine:
    """No enforcement — establishes the attack-prevention floor."""

    name = "allow-all"

    def decide(self, task: BenchmarkTask, event: BenchmarkEvent) -> Decision:
        return Decision(True, "no enforcement", self.name)


class DenyAllEngine:
    """Blocks everything — establishes the friction ceiling."""

    name = "deny-all"

    def decide(self, task: BenchmarkTask, event: BenchmarkEvent) -> Decision:
        return Decision(False, "deny all", self.name)


class ToolAllowlistEngine:
    """Naive RBAC: allow any call whose tool name was granted for the task."""

    name = "tool-allowlist"

    def decide(self, task: BenchmarkTask, event: BenchmarkEvent) -> Decision:
        from benchmarks.core.patterns import matches_any

        granted = (matches_any(event.tool_name, task.tool_patterns)
                   if task.tool_patterns is not None
                   else event.tool_name in task.allowed_tools)
        if granted:
            return Decision(True, f"tool {event.tool_name!r} on allowlist", self.name)
        return Decision(False, f"tool {event.tool_name!r} not on allowlist", self.name)


class CapabilityTokenEngine:
    """``resource:action`` capability match — the Biscuit token semantics."""

    name = "capability-token"

    def decide(self, task: BenchmarkTask, event: BenchmarkEvent) -> Decision:
        from benchmarks.core.patterns import capability_allows_patterns

        caps = normalize_capabilities(task.capabilities)
        allowed = (capability_allows_patterns(caps, event.resource, event.action)
                   if task.resource_patterns is not None
                   else capability_allows(caps, event.resource, event.action))
        if allowed:
            return Decision(True, f"capability {event.resource}:{event.action}", self.name)
        return Decision(False, f"no capability for {event.resource}:{event.action}", self.name)


class TaskScopeEngine:
    """Path- and resource-scoped mandate enforcement (``core.task_scope``).

    Composes the rung below rather than replacing it. A path-scoped
    (``agentauth.human_authorization.v1``) mandate compiles to an *empty*
    ``allowed_resources``, so scope alone would silently drop the
    ``resource:action`` check that ``capability-token`` enforces, and a
    connector-substitution attack would pass a higher rung while failing a
    lower one. Carrying the capability check forward makes the ladder monotone
    by construction instead of by coincidence of corpus.
    """

    name = "task-scope"

    def __init__(self) -> None:
        self._scopes: dict[str, TaskScope] = {}

    def _scope(self, task: BenchmarkTask) -> TaskScope:
        scope = self._scopes.get(task.task_id)
        if scope is None:
            scope = compile_task_scope(task.mandate)
            self._scopes[task.task_id] = scope
        return scope

    def _resource_allowed(self, scope: TaskScope, event: BenchmarkEvent) -> bool:
        if not scope.allowed_resources:
            return True
        return event.resource in scope.allowed_resources

    def decide(self, task: BenchmarkTask, event: BenchmarkEvent) -> Decision:
        scope = self._scope(task)
        # Both rungs below, carried forward, so the ladder is monotone by
        # construction rather than by coincidence of corpus. The tool allowlist
        # was missing and SLEIGHT caught it: the naive `tool-allowlist` rung
        # contained four attacks that the full stack allowed, because a task
        # whose scope is resource-shaped never re-asks whether the tool itself
        # was granted.
        from benchmarks.core.patterns import matches_any

        if task.tool_patterns is not None:
            if not matches_any(event.tool_name, task.tool_patterns):
                return Decision(False, f"tool {event.tool_name!r} not granted", self.name)
        elif task.allowed_tools and event.tool_name not in task.allowed_tools:
            return Decision(False, f"tool {event.tool_name!r} not granted", self.name)
        # Only when the task actually carries capabilities: a corpus with no
        # capability grant would otherwise be denied wholesale rather than
        # judged on scope.
        if task.capabilities and not capability_allows(
            normalize_capabilities(task.capabilities), event.resource, event.action
        ):
            return Decision(False, f"no capability for {event.resource}:{event.action}", self.name)
        # Global protected zones win over the goal's own path scope: no task
        # reads/writes credential stores, keys, or env files without an explicit
        # allow-listed exception (goal's allowed_paths).
        if event.path is not None and is_protected_path(
            event.path, allow_exceptions=set(scope.allowed_paths)
        ):
            return Decision(False, protected_reason(event.path) or "protected zone", self.name)
        if scope.allowed_actions and event.action not in scope.allowed_actions:
            return Decision(False, f"action {event.action!r} out of scope", self.name)
        if not self._resource_allowed(scope, event):
            return Decision(False, f"resource {event.resource!r} out of scope", self.name)
        if event.path is not None and not task_scope_allows_path(scope, event.path):
            return Decision(False, f"path {event.path!r} outside path scope", self.name)
        return Decision(True, "within task scope", self.name)


class TaskScopeInputBindingEngine(TaskScopeEngine):
    """Task scope PLUS commit-token argument binding.

    Mirrors ``verify_commit_token``'s ``arguments_hash`` check: when the user
    authorized a specific argument shape for a tool, mutated arguments (e.g. a
    swapped payee) invalidate authorization even if the tool and path are in
    scope. This is the layer that catches same-tool argument-tampering attacks.
    """

    name = "task-scope+binding"

    def __init__(self) -> None:
        super().__init__()
        self._authorized: dict[str, dict[str, set[str]]] = {}

    def _authorized_hashes(self, task: BenchmarkTask) -> dict[str, set[str]]:
        """Per-tool set of authorized argument-hashes (one per legitimate call)."""
        cached = self._authorized.get(task.task_id)
        if cached is None:
            cached = {
                tool: {hash_canonical_json(args) for args in shapes}
                for tool, shapes in task.authorized_args.items()
            }
            self._authorized[task.task_id] = cached
        return cached

    def decide(self, task: BenchmarkTask, event: BenchmarkEvent) -> Decision:
        base = super().decide(task, event)
        if not base.allowed:
            return Decision(base.allowed, base.reason, self.name)
        authorized = self._authorized_hashes(task).get(event.tool_name)
        # A bound tool (present with at least one authorized shape) admits only
        # calls whose exact arguments were authorized; per call, not per tool.
        if authorized:
            if hash_canonical_json(event.args) not in authorized:
                # Exception: an argument-less call to a bound READ tool. Binding
                # exists to stop an effect being redirected (a swapped payee, a
                # mutated path), and an empty argument set redirects nothing. It
                # is the agent asking the unfiltered version of a question it was
                # authorized to ask filtered: `list_invoices()` where
                # `list_invoices(status="pending")` was authorized.
                #
                # Found on ATIF, where it was the only source of false blocks in
                # the entire corpus (2 of 282 benign events, 0.71%). Measured
                # before and after across every corpus: containment unchanged on
                # fixture, RedCode, AgentHarm and ASB, argument-tampering
                # containment still 100%, and needle detection in the
                # long-trajectory tier still 100%. The broader version of this
                # fix, exempting all reads from binding, costs 13 points of
                # needle detection and was rejected on that evidence.
                #
                # What this does NOT cover is read-broadening as an attack: an
                # unfiltered read returns a superset of the authorized one. That
                # is an in-surface attack, uncontained by every per-call layer
                # including this one, and it belongs to the aggregate tier.
                # Gated on a POSITIVE read predicate, not on the complement of
                # the effect set. `classify_verb` falls back to `call` for
                # anything it does not recognise, and `call` is not in
                # _EFFECT_ACTIONS, so a bound CONSEQUENTIAL tool invoked with
                # its arguments stripped landed on the allow side of a rule
                # written for reads. Costs nothing on any corpus (measured on
                # all nine: no rate moves), so it is free defence in depth
                # against a tool whose verb we do not classify.
                if not event.args and event.action in _READ_ACTIONS:
                    return Decision(True, "unfiltered read of a bound tool", self.name)
                return Decision(False, "input binding: arguments not authorized for any call", self.name)
        return Decision(True, "within task scope; arguments bound", self.name)


class BudgetLadderEngine(TaskScopeInputBindingEngine):
    """Full stack: task scope + input binding + cumulative session budgets.

    Adds the aggregate-volume defense the lower rungs structurally cannot see.
    Every rung below judges each call in isolation, so an attacker can fragment
    an over-budget effect into many individually-valid calls (each a legal tool,
    action, path, and argument shape). This rung threads the task's events
    through the real ``SessionValueBudget`` / ``SessionCallBudget`` ledgers and
    refuses the call that would cross a requester-inherited ceiling.

    Budgets are stateful per task and consumed in event order (the runner
    replays a task's events contiguously). A ledger debits only calls the lower
    rungs already authorized, mirroring production: a blocked call never spends.
    Tasks with no budget wiring pass straight through.
    """

    name = "task-scope+binding+budget"

    def __init__(self) -> None:
        super().__init__()
        self._value: dict[str, object] = {}
        self._calls: dict[str, object] = {}

    def _ledgers(self, task: BenchmarkTask):
        if task.task_id not in self._value:
            self._value[task.task_id] = session_value_budget_from_mandate(
                task.mandate, tracked=task.value_tracked
            )
            self._calls[task.task_id] = session_call_budget_from_mandate(
                task.mandate, tracked=task.call_tracked
            )
        return self._value[task.task_id], self._calls[task.task_id]

    def decide(self, task: BenchmarkTask, event: BenchmarkEvent) -> Decision:
        base = super().decide(task, event)
        if not base.allowed:
            return Decision(False, base.reason, self.name)
        value_sess, call_sess = self._ledgers(task)
        value_res = value_sess.reserve(event.tool_name, event.args)
        if not value_res.allowed:
            return Decision(False, value_res.reason, self.name)
        call_res = call_sess.reserve(event.tool_name, event.args)
        if not call_res.allowed:
            value_res.release()
            return Decision(False, call_res.reason, self.name)
        # Authorized by every rung — the call proceeds and debits its ledgers.
        value_res.commit()
        call_res.commit()
        return Decision(True, "within scope, binding, and budget", self.name)


# --------------------------------------------------------------------------- #
# Engine-integration family: one policy carried across pluggable authorizers
# --------------------------------------------------------------------------- #
def _policy_evaluator(task: BenchmarkTask):
    """A local decision function encoding the task's capability policy.

    Stands in for an OPA/Cedar/OpenFGA sidecar: swap this closure for a thin
    client that posts the authorizer's input shape to the real engine. Holding
    the policy identical is the point — it isolates the engine integration.
    """
    caps = normalize_capabilities(task.capabilities)

    def evaluate(decision_input: dict) -> dict:
        # Extract (resource, action) from whichever input shape the authorizer
        # produced (OPA nests under "input"; Cedar/OpenFGA are flat).
        payload = decision_input.get("input", decision_input)
        resource = payload.get("resource") or decision_input.get("object", "")
        action = payload.get("action") or decision_input.get("relation", "")
        return {"allow": capability_allows(caps, resource, action)}

    return evaluate


class _ExternalEngine:
    """Wraps an ``authorizers.py`` factory around the shared policy evaluator."""

    def __init__(self, name: str, factory) -> None:
        self.name = name
        self._factory = factory
        self._authorizers: dict[str, object] = {}

    def _authorizer(self, task: BenchmarkTask):
        auth = self._authorizers.get(task.task_id)
        if auth is None:
            auth = self._factory(task)
            self._authorizers[task.task_id] = auth
        return auth

    def decide(self, task: BenchmarkTask, event: BenchmarkEvent) -> Decision:
        result = self._authorizer(task)(event.resource, event.action)
        allowed = bool(result.get("allowed"))
        provider = result.get("provider", self.name)
        return Decision(allowed, f"{provider} decision", self.name)


def opa_engine() -> _ExternalEngine:
    return _ExternalEngine(
        "opa",
        lambda task: opa_authorizer(_policy_evaluator(task), principal=task.task_id),
    )


def cedar_engine() -> _ExternalEngine:
    return _ExternalEngine(
        "cedar",
        lambda task: cedar_authorizer(_policy_evaluator(task), principal=task.task_id),
    )


def openfga_engine() -> _ExternalEngine:
    return _ExternalEngine(
        "openfga",
        lambda task: openfga_authorizer(_policy_evaluator(task), user=task.task_id),
    )


class VelocityLadderEngine(BudgetLadderEngine):
    """Full stack plus a rate limit calibrated on clean traffic.

    This rung exists because of a measured gap. `benchmarks/results/why_we_fail.md`
    found that 641 of 833 missed attacks carry NO TARGET AT ALL, with tool,
    resource and action all granted, so every rung below binds to something the
    action does not have. Velocity is the only deterministic signal that survives
    an action having no target: it asks whether the *rate* has left the shape of
    the task rather than where the action points.

    ## How the cap is chosen, and why the obvious way is wrong

    The first version of this engine set the cap from *the task under evaluation*
    at `1.5 x its own benign effect count`. That is invalid, and measurement says
    so plainly: on SLEIGHT, RedCode and ASB, 100% of attack-bearing tasks contain
    zero benign effect events, so every one of them was handed `cap = floor = 1`.
    The limit was a function of the label. It reported 24.7% containment on
    AgentHarm and 65.5% on SLEIGHT; neither number was real.

    The cap here is a single per-corpus constant, set at the *maximum* number of
    effect actions any CLEAN task performs, which is what an operator does with a
    fortnight of their own logs. It never consults the task being judged and
    never consults an attack event.

    The maximum rather than a high percentile, because the two differ in kind. At
    p99 the cap by construction trips on the busiest 1% of legitimate work, and
    it did: BFCL lost 0.4% of its benign side and tau2 0.1%, which broke the
    ladder's no-added-false-blocks invariant for no containment in return. At the
    observed maximum both go to zero and the containment is unchanged.

    Measured result on this evidence: **+0.0 points on every corpus**, at 0.0%
    false-block. An earlier revision of this docstring claimed +8.0 on AgentHarm.
    That came from the AgentHarm loader concatenating a behaviour's benign
    variant and its harmful twin into one trajectory, benign first, so the benign
    half consumed the rate budget and the harmful half was blocked for arriving
    late. The loader now emits them as two tasks and the gain is gone. See
    benchmarks/results/why_we_fail.md for the table.

    SLEIGHT gains nothing at any cap either, and there the tell is different:
    containment and false-block move together at every point (65.5/65.6,
    55.5/55.3, 49.7/49.8), so the mechanism was blocking a fraction of everything
    and being credited for the attack share.

    The rung ships because it costs nothing and is the only deterministic signal
    that survives an action having no target. Its containment claim rests on
    `benchmarks/burst.py`, which supplies the burst none of these corpora
    contains, not on anything measured here.

    A single cap shared across corpora is not viable either: RedCode's clean side
    runs to 32 effect actions per task and loses 17.4% of its benign traffic at
    the cap AgentHarm wants. The limit belongs in the mandate, per class of work
    (`agentauth.capabilities.velocity.velocity_from_mandate`), which is where
    production reads it from.
    """

    name = "task-scope+binding+budget+velocity"

    # Quantile of the clean volume distribution. 1.0 is the observed maximum;
    # anything lower trips on the operator's own busiest legitimate task.
    percentile = 1.0
    # Used only when a corpus has no clean task to calibrate on, in which case
    # there is nothing to learn from and an operator would fall back to a default.
    default_cap = 5
    floor = 1

    def __init__(self) -> None:
        super().__init__()
        self._cap: int | None = None
        self._velocity: dict[str, object] = {}

    @classmethod
    def calibrate(cls, tasks: list[BenchmarkTask]) -> int:
        """Cap from clean traffic. Attack events are never inspected."""
        from agentauth.capabilities.velocity import EFFECT_VERBS

        volumes = [
            sum(1 for e in t.events if e.action in EFFECT_VERBS)
            for t in tasks
            if not any(e.label is EventLabel.ATTACK for e in t.events)
        ]
        if not volumes:
            return cls.default_cap
        volumes.sort()
        idx = max(0, math.ceil(cls.percentile * len(volumes)) - 1)
        return max(cls.floor, volumes[idx])

    def observe_corpus(self, tasks: list[BenchmarkTask]) -> None:
        """Declare the cap for this class of work, once, before replay."""
        self._cap = self.calibrate(tasks)
        self._velocity.clear()

    def _limiter(self, task: BenchmarkTask):
        from agentauth.capabilities.velocity import (
            EFFECT_CLASS, SessionVelocity, VelocityConfig)

        limiter = self._velocity.get(task.task_id)
        if limiter is None:
            cap = self.default_cap if self._cap is None else self._cap
            # The cap is calibrated on TOTAL effect volume per clean task, so it
            # is enforced on the aggregate class, not per verb. The two used to
            # disagree: a cap of 9 derived from total volume was applied to each
            # of nine verbs separately, so a session could spend nine times what
            # was calibrated. It also made the 0.00% false-block a theorem rather
            # than a measurement, since a per-verb count is bounded by the task
            # total, which is bounded by the cap.
            limiter = SessionVelocity(config=VelocityConfig(
                limits={EFFECT_CLASS: (cap, 3600.0)}))
            self._velocity[task.task_id] = limiter
        return limiter

    def decide(self, task: BenchmarkTask, event: BenchmarkEvent) -> Decision:
        base = super().decide(task, event)
        if not base.allowed:
            return Decision(base.allowed, base.reason, self.name)
        limiter = self._limiter(task)
        # Deterministic clock: the replay has no real time, and the window only
        # has to be wide enough to hold one task. `try_acquire` rather than
        # check-then-record, because the two-call form is a race that let forty
        # concurrent actions through a cap of five.
        verdict = limiter.try_acquire(event.tool_name, event.action, now=0.0)
        if not verdict.allowed:
            return Decision(False, verdict.reason, self.name)
        return Decision(True, "within task scope, bound, budgeted and paced", self.name)


class DelegationLadderEngine(VelocityLadderEngine):
    """Full stack plus the question no rung below it asks: WHOSE authority.

    Every rung below judges the action. This one judges the principal. It reads
    the acting agent from ``event.meta["principal"]`` and the delegation that
    agent presented from ``task.meta["delegation"]["presenters"]``, and refuses
    an action the principal's own chain does not authorize even when the action
    itself is inside the task's mandate.

    ``task.meta["delegation"]`` absent means the task does not delegate, and the
    rung is a pass-through. That is what keeps the deterministic tier unchanged:
    none of RedCode, AgentHarm, ASB, SLEIGHT, IPI-Coding or AgentThreatBench has
    a second principal, so on all of them this engine is the rung below it,
    decision for decision.
    """

    name = "task-scope+binding+budget+velocity+delegation"

    def decide(self, task: BenchmarkTask, event: BenchmarkEvent) -> Decision:
        base = super().decide(task, event)
        if not base.allowed:
            return Decision(False, base.reason, self.name)
        wiring = (task.meta or {}).get("delegation")
        if not wiring:
            return Decision(True, base.reason, self.name)
        principal = (event.meta or {}).get("principal")
        if principal is None:
            # A delegating task with an unattributed action. Fail closed: an
            # action nobody signed for is the confused deputy's best disguise.
            return Decision(False, "action carries no acting principal", self.name)
        boundary = wiring["boundary"]
        verdict = boundary.authorize(
            principal=principal,
            resource=event.resource,
            action=event.action,
            envelope=wiring["presenters"].get(principal),
        )
        if not verdict.allowed:
            return Decision(False, f"{verdict.rule}: {verdict.reason}", self.name)
        return Decision(True, "authorized for this principal", self.name)


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #
LADDER = [
    "allow-all",
    "tool-allowlist",
    "capability-token",
    "task-scope",
    "task-scope+binding",
    "task-scope+binding+budget",
    "task-scope+binding+budget+velocity",
    "deny-all",
]


def _deployable_stack_engine():
    from benchmarks.core.stack_engine import DeployableStackEngine

    return DeployableStackEngine(name="deployable-stack", treat_step_up="block")


def _deployable_stack_engine_permissive():
    """The pessimistic supervised reading: a human approves every step-up.

    Reported beside the other because the gap between them IS the contribution of
    the step-up path, and `adaptive_stack_labelfree.md` measured that gap at 74
    points on one attack class.
    """
    from benchmarks.core.stack_engine import DeployableStackEngine

    return DeployableStackEngine(name="deployable-stack-stepup-allow",
                                 treat_step_up="allow")


def _deployable_stack_with_counts():
    """The goal-derived count rung, which is OFF in what ships.

    Kept as an arm so its contribution stays attributable by difference. The
    difference is why it is off: +1.2 points of containment for +10.2 points of
    false positives, per session on AgentHarm.
    """
    from benchmarks.core.stack_engine import DeployableStackEngine

    return DeployableStackEngine(name="deployable-stack-with-counts",
                                 treat_step_up="block", derive_counts=True)


def _deployable_stack_no_envelope():
    """What every structural analysis measured before the envelope was wired."""
    from benchmarks.core.stack_engine import DeployableStackEngine

    return DeployableStackEngine(name="deployable-stack-no-envelope",
                                 treat_step_up="block", with_envelope=False)


def build_engines(names: list[str] | None = None) -> list[DecisionEngine]:
    factory = {
        "allow-all": AllowAllEngine,
        "deny-all": DenyAllEngine,
        "tool-allowlist": ToolAllowlistEngine,
        "capability-token": CapabilityTokenEngine,
        "task-scope": TaskScopeEngine,
        "task-scope+binding": TaskScopeInputBindingEngine,
        "task-scope+binding+budget": BudgetLadderEngine,
        "task-scope+binding+budget+velocity": VelocityLadderEngine,
        "task-scope+binding+budget+velocity+delegation": DelegationLadderEngine,
        # Deliberately NOT in LADDER: this rung is under evaluation, and adding
        # it to the shipped ladder before benchmarks/density_sweep.py says it
        # earns a place would be the claim rather than the measurement.
        "task-scope+binding+budget+velocity+density": DensityLadderEngine,
        # Also out of LADDER pending the friction measurement below.
        "task-scope+binding+budget+velocity+density+staging": StagingLadderEngine,
        # The SHIPPED product, behind the same protocol as the ladder rungs.
        # It was absent here while `adaptive_stack.py` used it directly, so every
        # structural analysis that went through `build_engines` measured the
        # ablation ladder and reported it as the system. The ladder tops out
        # below the stack: no intent envelope, no parameter provenance, no
        # confidentiality flow, no session rules.
        "deployable-stack": _deployable_stack_engine,
        # The count rung, attributed by difference: same stack, envelope with and
        # without goal-derived occurrence counts.
        "deployable-stack-with-counts": _deployable_stack_with_counts,
        "deployable-stack-no-envelope": _deployable_stack_no_envelope,
        "deployable-stack-stepup-allow": _deployable_stack_engine_permissive,
        "opa": opa_engine,
        "cedar": cedar_engine,
        "openfga": openfga_engine,
    }
    selected = names or LADDER
    unknown = [n for n in selected if n not in factory]
    if unknown:
        raise ValueError(f"unknown engine(s): {unknown}; known: {sorted(factory)}")
    return [factory[n]() for n in selected]


class DensityLadderEngine(VelocityLadderEngine):
    """Full stack plus a goal-conditioned density over *which* resource is touched.

    ## Why this rung exists

    Every rung below discriminates by membership: is this tool/resource/path in
    the grant. `benchmarks/generalize.py` measures what that costs. Holding every
    other dimension fixed and wildcarding the path grant by ONE segment:

        redcode              99.86% -> 33.29% contained
        ipi_coding          100.00% -> 30.00%
        agent_threat_bench  100.00% ->  0.00%

    while the tool dimension is free (no loss at all). So the flagship containment
    is one mechanism: the attack path is outside a literally enumerated set. An
    operator does not write mandates that way — they write `~/repo/**` — and at
    that grant the measured containment is 0-33%.

    A density does not have the membership property. `repo/app/summary.txt` and
    `repo/.git/config` sit inside the identical wildcard, but under a given goal
    the cohort has touched one many times and the other never, so they score
    decades apart. The grant stays wide enough for a human to write; the density
    discriminates inside it. This is the move human UEBA makes and this ladder
    did not: access is the ACL, and *having never opened these files* is the
    baseline.

    ## How the threshold is set, and why the obvious way is wrong

    The same trap the velocity rung documents applies here and is avoided the
    same way. The threshold is NOT set from the task under evaluation and never
    consults an attack event. It is a per-corpus constant derived from clean
    traffic through `observe_corpus`, which the runner feeds the calibration half
    of the CLEAN tasks only.

    That calibration half is then split AGAIN: the trie is fit on one slice and
    the threshold is the `1-alpha` quantile of surprises on a disjoint slice.
    Fitting and thresholding on the same events makes every calibration point
    in-corridor by construction, which sets the threshold at the ceiling and
    reports a false-block rate that is arithmetic rather than measurement. That
    is precisely the defect `detector.py` documents for its own conformal layer,
    and the fix is the same: split.

    So `alpha` is a declared false-alarm budget and the scored false-block rate
    should land near it. A rung that returns containment while its false-block
    rate sits far above `alpha` is not working, and the number will say so.
    """

    name = "task-scope+binding+budget+velocity+density"

    def __init__(self, *, alpha: float = 0.01, fit_frac: float = 0.6,
                 min_calibration_actions: int = 60) -> None:
        super().__init__()
        self.alpha = alpha
        self.fit_frac = fit_frac
        # Counted in benign ACTIONS, not tasks. A density over resource targets
        # is estimated from targets, and the two units differ by an order of
        # magnitude in exactly the place it matters: RedCode ships 50 clean
        # tasks carrying 344 benign events, so a task-counted floor of 30 made
        # the rung abstain on a corpus that had 172 calibration actions
        # available. Getting this unit wrong reads as "the mechanism does not
        # work" when it means "the mechanism was never switched on".
        self.min_calibration_actions = min_calibration_actions
        self._scorer = None
        self._threshold: float | None = None

    # -- calibration ------------------------------------------------------- #
    @staticmethod
    def _bucket(task: BenchmarkTask) -> str:
        """Goal bucket, matching ``detector_eval``'s convention."""
        kind = task.meta.get("goal_kind")
        if not kind and task.meta.get("category"):
            kind = f"sleight:{task.meta['category']}"
        return str(kind or task.meta.get("suite") or "task")

    @staticmethod
    def _actions(task: BenchmarkTask, *, benign_only: bool = True):
        from agentauth.capabilities.monitor.action import Action

        out = []
        for i, event in enumerate(task.events):
            if benign_only and event.label is EventLabel.ATTACK:
                continue
            out.append(Action(step=i, tool=event.tool_name,
                              resource=event.resource, verb=event.action,
                              args=dict(event.args),
                              meta={"path": event.path} if event.path else {}))
        return out

    def _trajectory(self, task: BenchmarkTask, actions):
        from agentauth.capabilities.monitor.action import Trajectory
        from agentauth.capabilities.scoping.goal import GoalSpec

        return Trajectory(
            goal=GoalSpec(query_id=task.task_id, summary="",
                          allow_resources=[],
                          structured_intent={"kind": self._bucket(task)}),
            actions=actions,
        )

    def observe_corpus(self, tasks: list[BenchmarkTask]) -> None:
        from agentauth.capabilities.monitor.scoring.target import TargetDensityScorer

        # The rung below calibrates through the SAME hook. Overriding it without
        # delegating leaves the velocity cap unset, and an uncalibrated cap
        # refuses clean traffic: the first run of this engine reported 16.28%
        # false-block and +0.0 containment, all of it from the rung below, while
        # the density itself had abstained. A composed rung must calibrate what
        # it composes.
        super().observe_corpus(tasks)

        # Never calibrate on a task that carries an attack, even when the runner
        # offers one. ``_calibration_split`` falls back to (tasks, tasks) for a
        # corpus with fewer than two clean tasks — ASB, InjecAgent and SLEIGHT
        # all hit that path — which would hand this rung the very sessions it is
        # about to judge. Filtering benign EVENTS out of an attack task is not
        # enough: the task is still in the scored set, so the baseline would be
        # fit in-sample and its false-block rate would be arithmetic.
        clean = [t for t in tasks
                 if not any(e.label is EventLabel.ATTACK for e in t.events)]
        usable = [t for t in clean if self._actions(t)]
        if sum(len(self._actions(t)) for t in usable) < self.min_calibration_actions:
            # Too little clean traffic to estimate a density from. Abstain
            # entirely rather than ship an uncalibrated threshold: this rung must
            # degrade to the rung below, never to blocking on no evidence.
            self._scorer = None
            self._threshold = None
            return

        ordered = list(usable)
        random.Random(f"density:{len(usable)}").shuffle(ordered)
        cut = max(1, int(len(ordered) * self.fit_frac))
        fit_tasks, cal_tasks = ordered[:cut], ordered[cut:]
        if not cal_tasks:
            self._scorer = None
            self._threshold = None
            return

        scorer = TargetDensityScorer()
        scorer.fit([self._trajectory(t, self._actions(t)) for t in fit_tasks])

        held: list[float] = []
        for task in cal_tasks:
            traj = self._trajectory(task, self._actions(task))
            held.extend(s.surprise for s in scorer.surprise(traj))
        if not held:
            self._scorer = None
            self._threshold = None
            return

        held.sort()
        # Block above the (1-alpha) quantile of held-out clean surprise. The
        # +1 is the conformal correction: with n calibration points the finest
        # achievable rate is 1/(n+1), and rounding down instead would promise a
        # budget the sample cannot support.
        idx = min(len(held) - 1,
                  int(math.ceil((len(held) + 1) * (1 - self.alpha))) - 1)
        self._threshold = held[idx]
        self._scorer = scorer

    # -- decision ---------------------------------------------------------- #
    def decide(self, task: BenchmarkTask, event: BenchmarkEvent) -> Decision:
        below = super().decide(task, event)
        if not below.allowed:
            return below
        if self._scorer is None or self._threshold is None:
            return below
        actions = self._actions(task, benign_only=False)
        idx = next((i for i, e in enumerate(task.events)
                    if e.event_id == event.event_id), None)
        if idx is None or idx >= len(actions):
            return below
        traj = self._trajectory(task, actions)
        # The bucket MUST come from the same function the scorer keyed its tries
        # with. ``TargetDensityScorer.fit`` buckets via ``goal_bucket(traj)``,
        # which prefixes the kind to ``goal:coding-agent``; passing the raw
        # ``coding-agent`` here missed every lookup and the rung silently
        # abstained on all 479 attacks it was handed while still reporting a
        # fitted scorer and a plausible threshold. A key derived two ways is a
        # key derived wrongly.
        from agentauth.capabilities.monitor.scoring.ngram import goal_bucket

        bucket = goal_bucket(traj)
        # Readiness is enforced inside ``segment_surprises`` as a DEPTH, not as a
        # per-bucket boolean. A boolean gate here was tried and is wrong in both
        # directions: RedCode's root is estimated from 123 observations over 2
        # children (escape 0.003, a sharp boundary worth enforcing) while its
        # depth-1 namespace has 68 targets over the same traffic, 1.8 apiece,
        # which cannot separate anything. One flag either discards the root or
        # claims the leaves. The scorer now stops contributing surprise at the
        # depth it stops having evidence, so the limit is structural.
        bits = self._scorer.segment_surprises(bucket, actions[idx])
        if not bits:
            return below  # no baseline for this bucket: abstain
        surprise = max(bits)
        if surprise > self._threshold:
            return Decision(
                False,
                f"target density: {surprise:.1f} bits > {self._threshold:.1f} "
                f"clean ceiling ({self._scorer.explain(traj, actions[idx])})",
                self.name,
            )
        return below


class StagingLadderEngine(DensityLadderEngine):
    """Full stack plus the secret-to-publication flow the scope rungs cannot see.

    ``benchmarks/results/in_scope_exfiltration.md``: against an oracle attacker
    the ladder below this rung contains in-scope data staging at exactly the rate
    ``allow-all`` does — identical escaped-task sets, not merely similar. The
    attack is ``read:/app/.env -> write:/app/README.md`` and every rung
    discriminates on a dimension it does not move.

    The predicate here is the one the mandate could not express: **once a session
    has read a SECRET-classed object, a write to a PUBLICATION-classed object is
    refused.** It is deliberately about object CLASS rather than path, because
    path is precisely what the attack keeps legal.

    ## Session state, and why that is the point

    Every rung below is a pure function of one action. This one is not, and it
    cannot be: neither half of the attack is suspicious alone. Reading ``.env``
    is what a build agent does; writing a README is what a documentation agent
    does. Only the pair, in one session, is evidence — which is the same
    structure as the budget rungs, and the reason this composes with them rather
    than duplicating them.

    ## What it deliberately does NOT do

    It does not read file contents to check whether the write actually carries
    the secret. In replay there are no contents, and in deployment a content
    check is the confidentiality flow tracker's job — this rung is the coarse
    metadata gate that runs when the tracker has nothing to look at. The cost is
    a real false-block on a session that legitimately reads a credential and
    later edits documentation, which is why the honest deployment posture is
    STEP_UP rather than DENY. The benchmark ladder has no step-up outcome, so it
    is scored at its strictest here and the friction column is the true cost.
    """

    name = "task-scope+binding+budget+velocity+density+staging"

    def __init__(self, **kw) -> None:
        super().__init__(**kw)
        self._read_secret: set[str] = set()

    @staticmethod
    def _target(event: BenchmarkEvent) -> str:
        return event.path or event.resource or ""

    def decide(self, task: BenchmarkTask, event: BenchmarkEvent) -> Decision:
        below = super().decide(task, event)
        if not below.allowed:
            return below

        from agentauth.capabilities.hardening.object_class import (
            ObjectClass, classify)

        target = self._target(event)
        kind = classify(target)
        verb = (event.action or "").lower()

        # Reads are recorded per TASK, not globally: a benchmark replays many
        # independent sessions through one engine instance, and leaking state
        # between them would refuse writes on the strength of a secret read in
        # somebody else's session.
        if kind is ObjectClass.SECRET and verb in _READ_ACTIONS:
            self._read_secret.add(task.task_id)
            return below

        if kind is ObjectClass.PUBLICATION and verb not in _READ_ACTIONS:
            if task.task_id in self._read_secret:
                return Decision(
                    False,
                    f"in-scope staging: publication-classed target {target!r} "
                    f"written after a secret-classed read in this session",
                    self.name,
                )
        return below
