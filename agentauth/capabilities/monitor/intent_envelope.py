"""The Intent Envelope — a goal-derived, history-free safety envelope.

This is the specification-based, RSS-style core of the behavioral layer. It is
compiled from the *sealed goal* (never from a corpus of past runs), so it works
on a brand-new task type and on a one-step run, and it cannot be prompt-injected
because it is fixed at seal time from trusted control-plane data.

The envelope is a typed, optionally-ordered plan over action classes:

- **membership**: which tools, verbs, and resource classes are plausible for the
  goal (from ``structured_intent`` and the goal's allowed resources);
- **order** (optional): a sequence of phases the task is expected to move
  through, e.g. read-the-invoices before you pay them. Declared under
  ``structured_intent["phases"]``.

Conformance is a token replay of the trace against the plan (borrowed from
process-mining): each action is classified as in-plan or as a typed deviation
(off-tool, off-verb, off-resource, or out-of-order). The detector / broker turn
those deviations into decisions via the two-signal gate (deviation × consequence).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agentauth.capabilities.monitor.action import Action, Trajectory, resource_class
from agentauth.capabilities.monitor.ontology import ToolOntology
from agentauth.capabilities.scoping.goal import GoalSpec

INTENT_ENVELOPE_SCHEMA = "agent-receipts.intent-envelope.v1"


class Deviation(str, Enum):
    IN_PLAN = "in-plan"
    OFF_TOOL = "off-tool"
    OFF_VERB = "off-verb"
    OFF_RESOURCE = "off-resource"
    OUT_OF_ORDER = "out-of-order"
    OFF_SLOT = "off-slot"


class SlotSource(str, Enum):
    """Where a typed-plan argument slot may be filled from."""

    GOAL = "goal"                 # literal in the sealed goal
    TRUSTED_READ = "trusted_read"  # structured / containing-object grounded
    FREE = "free"                 # unconstrained (reads, searches)


@dataclass(frozen=True)
class ParameterSlot:
    name: str
    source: SlotSource

    def to_dict(self) -> dict:
        return {"name": self.name, "source": self.source.value}

    @classmethod
    def from_dict(cls, raw: dict) -> "ParameterSlot":
        return cls(name=str(raw["name"]), source=SlotSource(raw.get("source", "free")))


@dataclass(frozen=True)
class CallTemplate:
    """A declarative call shape with provenance-typed argument slots.

    The planner emits these from the sealed goal only. At authorize time a
    benign call matches a template's tool/verb and each constrained slot's
    provenance; an injected call fails the slot check even when the tool is
    on the allow-list.
    """

    tool: str
    verb_class: str = ""
    slots: tuple[ParameterSlot, ...] = ()

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "verb_class": self.verb_class,
            "slots": [s.to_dict() for s in self.slots],
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "CallTemplate":
        slots = tuple(ParameterSlot.from_dict(s) for s in raw.get("slots", [])
                      if isinstance(s, dict))
        return cls(tool=str(raw["tool"]), verb_class=str(raw.get("verb_class", "")),
                   slots=slots)

    def matches_shape(self, action: Action) -> bool:
        if action.tool != self.tool:
            return False
        if self.verb_class and action.verb.lower() != self.verb_class.lower():
            # Also accept verb-class groupings (send/transfer/post).
            from agentauth.capabilities.replan import verb_class as vc
            return vc(action.verb) == self.verb_class or vc(action.verb) == vc(self.verb_class)
        return True

@dataclass(frozen=True)
class Phase:
    tools: frozenset[str] = frozenset()
    verbs: frozenset[str] = frozenset()
    resource_classes: frozenset[str] = frozenset()
    min: int = 0            # required occurrences (a landmark when > 0)
    repeatable: bool = True

    def to_dict(self) -> dict:
        return {
            "tools": sorted(self.tools), "verbs": sorted(self.verbs),
            "resource_classes": sorted(self.resource_classes),
            "min": self.min, "repeatable": self.repeatable,
        }

    def matches(self, action: Action) -> bool:
        rc = resource_class(action.resource)
        return bool(
            (self.tools and action.tool in self.tools)
            or (self.verbs and action.verb.lower() in self.verbs)
            or (self.resource_classes and rc in self.resource_classes)
        )


@dataclass(frozen=True)
class StepConformance:
    step: int
    deviation: Deviation
    reason: str

    @property
    def in_plan(self) -> bool:
        return self.deviation is Deviation.IN_PLAN


@dataclass
class IntentConformance:
    steps: list[StepConformance] = field(default_factory=list)

    @property
    def conforms(self) -> bool:
        return all(s.in_plan for s in self.steps)

    @property
    def deviations(self) -> list[StepConformance]:
        return [s for s in self.steps if not s.in_plan]

    @property
    def fitness(self) -> float:
        if not self.steps:
            return 1.0
        return sum(s.in_plan for s in self.steps) / len(self.steps)


@dataclass
class IntentEnvelope:
    allowed_tools: frozenset[str]
    allowed_verbs: frozenset[str]
    allowed_resource_classes: frozenset[str]
    phases: tuple[Phase, ...] = ()
    # Partial order over ``phases`` (indices into ``phases``): ``(i, j)`` means
    # phase i must precede phase j. ``None`` ⇒ legacy total order (each phase must
    # follow every lower-indexed phase). An explicit set (possibly empty) enforces
    # ONLY the listed edges — the causal / precondition / danger edges that carry
    # security signal — while permitting any interleaving of independent phases.
    # Empty set ⇒ membership only, no ordering constraint.
    phase_order: frozenset[tuple[int, int]] | None = None
    # Multi-modal plan: alternative mode paths (each an ordered phase sequence).
    # The trace conforms if it is consistent with at least one mode. Empty ⇒ the
    # single ``phases`` list is the only mode (Phases A/B/C1/C2 behavior).
    modes: tuple[tuple[Phase, ...], ...] = ()
    # Behavior-tree plan (optional). When present, conformance runs over it via an
    # NFA (no linearization / no mode explosion) and is authoritative over
    # ``phases`` / ``modes``. Typed ``object`` to avoid a circular import.
    plan_tree: object | None = None
    # Feasibility model (optional): the facts the task must achieve, the facts
    # true at the start, and the tool ontology to reason with.
    goal_conditions: frozenset[str] = frozenset()
    initial_facts: frozenset[str] = frozenset()
    ontology: ToolOntology | None = None
    # Typed call templates with provenance-typed slots. Empty ⇒ legacy
    # tool/verb/resource membership only.
    call_templates: tuple[CallTemplate, ...] = ()

    @classmethod
    def from_goal(cls, goal: GoalSpec, *, ontology: ToolOntology | None = None) -> "IntentEnvelope":
        intent = goal.structured_intent or {}
        phases = _parse_phases(intent.get("phases"))
        templates = _parse_templates(intent.get("call_templates"))

        tools = set(intent.get("tools") or [])
        verbs = {str(v).lower() for v in (intent.get("verbs") or [])}
        rclasses = {resource_class(r) for r in goal.allow_resources}
        # Tools implied by the goal's allowed resources (mcp:tool:<name>).
        for r in goal.allow_resources:
            if r.startswith("mcp:tool:"):
                tools.add(r.rsplit(":", 1)[-1])
        # If phases are declared, the plan is their union.
        for p in phases:
            tools |= set(p.tools)
            verbs |= set(p.verbs)
            rclasses |= set(p.resource_classes)
        for t in templates:
            tools.add(t.tool)
            if t.verb_class:
                verbs.add(t.verb_class.lower())

        onto = ontology or (ToolOntology.from_dict(intent["ontology"])
                            if isinstance(intent.get("ontology"), list) else None)
        return cls(
            allowed_tools=frozenset(tools),
            allowed_verbs=frozenset(verbs),
            allowed_resource_classes=frozenset(rclasses),
            phases=phases,
            goal_conditions=frozenset(str(g) for g in intent.get("goal_conditions", [])),
            initial_facts=frozenset(str(f) for f in intent.get("initial_facts", [])),
            ontology=onto,
            call_templates=templates,
        )

    def check_slots(
        self,
        action: Action,
        *,
        provenance: Any | None = None,
        goal_text: str = "",
        goal_named_objects: set[str] | None = None,
    ) -> StepConformance | None:
        """Return an OFF_SLOT deviation when a matching template's slots fail.

        No templates, or no matching template shape, means this check is a
        no-op (membership / phases still apply). A matching template with a
        ``trusted_read`` slot requires structured grounding via provenance.
        """
        if not self.call_templates:
            return None
        matching = [t for t in self.call_templates if t.matches_shape(action)]
        if not matching:
            return None
        template = matching[0]
        for slot in template.slots:
            if slot.source is SlotSource.FREE:
                continue
            value = action.args.get(slot.name)
            if value is None:
                # Also accept common destination aliases.
                for alt in ("to", "recipient", "url", "destination", "address"):
                    if alt in action.args:
                        value = action.args[alt]
                        break
            if value is None:
                continue
            if slot.source is SlotSource.GOAL:
                if str(value) not in goal_text:
                    return StepConformance(
                        action.step, Deviation.OFF_SLOT,
                        f"slot {slot.name!r} value not present in sealed goal")
                continue
            if slot.source is SlotSource.TRUSTED_READ:
                if provenance is None:
                    return StepConformance(
                        action.step, Deviation.OFF_SLOT,
                        f"slot {slot.name!r} requires trusted_read provenance")
                from agentauth.capabilities.parameter_provenance import DestinationTrust
                trust, reason = provenance.check_destination(
                    value, goal_named_objects=goal_named_objects)
                if trust is not DestinationTrust.ALLOW:
                    return StepConformance(
                        action.step, Deviation.OFF_SLOT,
                        f"slot {slot.name!r}: {reason}")
        return None
    # -- membership ----------------------------------------------------------
    def _membership(self, action: Action) -> StepConformance | None:
        rc = resource_class(action.resource)
        if self.allowed_tools and action.tool not in self.allowed_tools:
            return StepConformance(action.step, Deviation.OFF_TOOL,
                                   f"tool {action.tool!r} not in the goal's plan")
        if self.allowed_verbs and action.verb.lower() not in self.allowed_verbs:
            return StepConformance(action.step, Deviation.OFF_VERB,
                                   f"verb {action.verb!r} not expected for the goal")
        if self.allowed_resource_classes and rc not in self.allowed_resource_classes:
            return StepConformance(action.step, Deviation.OFF_RESOURCE,
                                   f"resource class {rc!r} outside the goal surface")
        return None

    # -- conformance ---------------------------------------------------------
    def _mode_paths(self) -> tuple[tuple[Phase, ...], ...]:
        return self.modes if self.modes else (self.phases,)

    def _plan_tools(self) -> frozenset[str]:
        """Tools that appear in some mode's phases (a plan step in any mode)."""
        tools: set[str] = set()
        for mode in self._mode_paths():
            for phase in mode:
                tools |= phase.tools
        return frozenset(tools)

    def _assess_phases(self, traj: Trajectory, phases: tuple[Phase, ...]) -> IntentConformance:
        steps: list[StepConformance] = []
        satisfied = [0] * len(phases)
        plan_tools = self._plan_tools()
        mode_tools = frozenset().union(*(p.tools for p in phases)) if phases else frozenset()
        for action in traj.actions:
            off = self._membership(action)
            if off is not None:
                steps.append(off)
                continue
            if not phases:
                steps.append(StepConformance(action.step, Deviation.IN_PLAN, "in plan"))
                continue
            matching = [i for i, p in enumerate(phases) if p.matches(action)]
            if not matching:
                # A tool that is a plan step in ANOTHER mode is off THIS plan (mode
                # separation). A tool in no mode's plan is auxiliary and permitted.
                if action.tool in plan_tools and action.tool not in mode_tools:
                    steps.append(StepConformance(
                        action.step, Deviation.OFF_TOOL,
                        f"{action.tool!r} belongs to a different plan than this mode"))
                    continue
                steps.append(StepConformance(action.step, Deviation.IN_PLAN, "in plan"))
                continue
            target = matching[0]
            # Which phases must precede `target`. Under a partial order, only the
            # phases with an explicit edge into `target`; independent phases carry
            # no constraint. `phase_order` is meaningful for the single-mode plan;
            # with alternative modes we keep the legacy total order.
            if self.phase_order is not None and not self.modes:
                predecessors = [i for (i, j) in self.phase_order if j == target]
            else:
                predecessors = list(range(target))
            # A required predecessor phase (min>0) not yet met is a missing landmark.
            missing = next(
                (i for i in predecessors
                 if phases[i].min > 0 and satisfied[i] < phases[i].min),
                None,
            )
            if missing is not None:
                steps.append(StepConformance(
                    action.step, Deviation.OUT_OF_ORDER,
                    f"{action.verb} {action.tool} before required earlier phase {missing}"))
                continue
            satisfied[target] += 1
            steps.append(StepConformance(action.step, Deviation.IN_PLAN, "in plan"))
        return IntentConformance(steps=steps)

    def assess(self, traj: Trajectory) -> IntentConformance:
        """Conformance under the best-explaining mode (a conforming one if any)."""
        if self.plan_tree is not None:
            from agentauth.capabilities.monitor.behavior_tree import tree_conformance
            return tree_conformance(self, traj)
        best: IntentConformance | None = None
        for phases in self._mode_paths():
            conf = self._assess_phases(traj, phases)
            if conf.conforms:
                return conf
            if best is None or len(conf.deviations) < len(best.deviations):
                best = conf
        return best or IntentConformance(steps=[])

    def last_deviation(self, traj: Trajectory) -> StepConformance | None:
        """Deviation of the most recent action, unless SOME mode still explains
        the whole trace (the MultiPath 'track any live anchor' rule)."""
        if self.plan_tree is not None:
            from agentauth.capabilities.monitor.behavior_tree import tree_conformance
            steps = tree_conformance(self, traj).steps
            last = steps[-1] if steps else None
            return None if (last is None or last.in_plan) else last
        candidate: StepConformance | None = None
        for phases in self._mode_paths():
            conf = self._assess_phases(traj, phases)
            if conf.conforms:
                return None  # this mode is alive and explains the trace
            last = conf.steps[-1] if conf.steps else None
            if candidate is None and last is not None and not last.in_plan:
                candidate = last
        return candidate

    # -- feasibility (the MPC "is the goal still reachable?" check) -----------
    def feasible(self, traj: Trajectory) -> tuple[bool, str]:
        """True if every goal condition is still reachable after this trace.

        Replays the trace's effects to get the current world and the set of
        facts irreversibly destroyed, then does a delete-relaxation forward
        reachability (the classic h_max closure) over the tool ontology. A goal
        condition that can no longer be reached means the mission was steered
        somewhere it cannot be completed from: the memo's "harmless refactor in
        one commit that breaks something in the next." No history required.
        """
        if not self.goal_conditions or self.ontology is None:
            return True, "no feasibility model"
        world = set(self.initial_facts)
        dead: set[str] = set()
        for action in traj.actions:
            spec = self.ontology.spec(action.tool)
            if spec is None:
                continue
            world |= spec.establishes
            world -= spec.destroys
            if not spec.reversible:
                dead |= spec.destroys  # permanently gone; no tool can re-achieve it
        reachable = self._reachable(world, dead)
        unmet = sorted(g for g in self.goal_conditions if g not in reachable)
        if unmet:
            return False, f"no feasible completion: goal condition(s) {unmet} unreachable"
        return True, "feasible"

    def _reachable(self, world: set[str], dead: set[str]) -> set[str]:
        reachable = set(world) - dead
        changed = True
        while changed:
            changed = False
            for spec in self.ontology.specs.values():
                if spec.preconditions <= reachable:
                    for fact in spec.establishes:
                        if fact not in reachable and fact not in dead:
                            reachable.add(fact)
                            changed = True
        return reachable

    def is_satisfiable(self) -> tuple[bool, str]:
        """Can the goal conditions be reached at all, from the initial facts, with
        the available tools? The Veritas 'logical consistency' check on the plan
        itself: a plan whose goal is unreachable is incoherent and must not be
        sealed. Reuses the same delete-relaxation reachability as feasibility."""
        if not self.goal_conditions or self.ontology is None:
            return True, "no feasibility model"
        reachable = self._reachable(set(self.initial_facts), set())
        unmet = sorted(g for g in self.goal_conditions if g not in reachable)
        if unmet:
            return False, f"goal condition(s) {unmet} unreachable from initial facts"
        return True, "satisfiable"

    def missing_landmarks(self, traj: Trajectory) -> list[int]:
        """Required phases (min>0) not yet satisfied — the plan's landmarks."""
        satisfied = [0] * len(self.phases)
        for action in traj.actions:
            if self._membership(action) is not None:
                continue
            for i, phase in enumerate(self.phases):
                if phase.matches(action):
                    satisfied[i] += 1
                    break
        return [i for i, p in enumerate(self.phases)
                if p.min > 0 and satisfied[i] < p.min]

    # -- serialization (so the envelope can be signed as control-plane data) --
    def to_dict(self) -> dict:
        return {
            "schema": INTENT_ENVELOPE_SCHEMA,
            "allowed_tools": sorted(self.allowed_tools),
            "allowed_verbs": sorted(self.allowed_verbs),
            "allowed_resource_classes": sorted(self.allowed_resource_classes),
            "phases": [p.to_dict() for p in self.phases],
            "phase_order": (None if self.phase_order is None
                            else sorted([i, j] for (i, j) in self.phase_order)),
            "modes": [[p.to_dict() for p in mode] for mode in self.modes],
            "plan_tree": _plan_tree_to_dict(self.plan_tree),
            "goal_conditions": sorted(self.goal_conditions),
            "initial_facts": sorted(self.initial_facts),
            "ontology": self.ontology.to_dict() if self.ontology else [],
            "call_templates": [t.to_dict() for t in self.call_templates],
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "IntentEnvelope":
        return cls(
            allowed_tools=frozenset(raw.get("allowed_tools", [])),
            allowed_verbs=frozenset(raw.get("allowed_verbs", [])),
            allowed_resource_classes=frozenset(raw.get("allowed_resource_classes", [])),
            phases=_parse_phases(raw.get("phases")),
            phase_order=(None if raw.get("phase_order") is None
                         else frozenset((int(i), int(j)) for i, j in raw["phase_order"])),
            modes=tuple(_parse_phases(mode) for mode in raw.get("modes", [])),
            plan_tree=_plan_tree_from_dict(raw.get("plan_tree")),
            goal_conditions=frozenset(raw.get("goal_conditions", [])),
            initial_facts=frozenset(raw.get("initial_facts", [])),
            ontology=ToolOntology.from_dict(raw["ontology"]) if raw.get("ontology") else None,
            call_templates=_parse_templates(raw.get("call_templates")),
        )

def sign_intent_envelope(envelope: IntentEnvelope, *, key) -> dict:
    """Sign an envelope as trusted control-plane data, like a mandate.

    The envelope is fixed at goal-seal time; signing makes it tamper-evident so a
    runtime gateway (or an auditor) can confirm the plan it enforces is the one
    the control plane sealed, and nothing the agent later reads has altered it.
    """
    document = envelope.to_dict()
    return {"schema": INTENT_ENVELOPE_SCHEMA, "document": document,
            "signature": key.sign(document)}


def verify_intent_envelope(signed: dict, *, trusted_keys=None) -> tuple[bool, str | None]:
    """Verify a signed envelope's integrity and (optionally) its signer.

    Mirrors the commit-token contract: a valid signature proves integrity, not
    authority. Pin ``trusted_keys`` (hex public keys or key_ids) to require that
    the control plane, not just any keyholder, sealed the plan.
    """
    from agentauth.core.signing import signature_key_id_matches, verify

    document = signed.get("document")
    signature = signed.get("signature")
    if not isinstance(document, dict) or not isinstance(signature, dict):
        return False, "malformed signed envelope"
    if not signature_key_id_matches(signature):
        return False, "signature key_id does not match public key"
    if not verify(document, signature):
        return False, "envelope signature invalid"
    if trusted_keys:
        pins = set(trusted_keys)
        if signature.get("public_key") not in pins and signature.get("key_id") not in pins:
            return False, "envelope signer is not a trusted control-plane key"
    return True, None


def _plan_tree_to_dict(tree):
    if tree is None:
        return None
    from agentauth.capabilities.monitor.behavior_tree import node_to_dict
    return node_to_dict(tree)


def _plan_tree_from_dict(raw):
    if not raw:
        return None
    from agentauth.capabilities.monitor.behavior_tree import node_from_dict
    return node_from_dict(raw)


def _parse_phases(raw) -> tuple[Phase, ...]:
    if not isinstance(raw, list):
        return ()
    out: list[Phase] = []
    for p in raw:
        if not isinstance(p, dict):
            continue
        out.append(Phase(
            tools=frozenset(str(t) for t in p.get("tools", [])),
            verbs=frozenset(str(v).lower() for v in p.get("verbs", [])),
            resource_classes=frozenset(str(c) for c in p.get("resource_classes", [])),
            min=int(p.get("min", 0)),
            repeatable=bool(p.get("repeatable", True)),
        ))
    return tuple(out)


def _parse_templates(raw) -> tuple[CallTemplate, ...]:
    if not isinstance(raw, list):
        return ()
    out: list[CallTemplate] = []
    for t in raw:
        if isinstance(t, dict) and "tool" in t:
            out.append(CallTemplate.from_dict(t))
    return tuple(out)