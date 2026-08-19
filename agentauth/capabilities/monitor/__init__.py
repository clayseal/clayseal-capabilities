"""Goal-conditional trajectory security: the behavioral enforcement layer.

Detects trajectories that are malicious even though every individual action is
permitted, by conditioning on the sealed goal and scoring the action stream with
a distribution-free false-alarm guarantee. See ``detector.TrajectoryDetector``.
"""
from __future__ import annotations

from agentauth.capabilities.monitor.action import (
    Action,
    ContextItem,
    Trajectory,
    TrustLevel,
    action_token,
    fine_action_token,
    trajectory_tokens,
)
from agentauth.capabilities.monitor.aml import AmlAnalytics, AmlVerdict
from agentauth.capabilities.monitor.behavior_tree import (
    NodeKind,
    PlanNode,
    envelope_from_tree,
    leaf,
    linearize,
    loop,
    selector,
    sequence,
)
from agentauth.capabilities.monitor.conformal import ConformalCalibrator, MondrianConformal
from agentauth.capabilities.monitor.consequence import (
    ConsequenceLevel,
    is_consequential,
)
from agentauth.capabilities.monitor.consequence import (
    classify as classify_consequence,
)
from agentauth.capabilities.monitor.declaration import (
    check_declaration_against_goal,
    seal_declaration,
)
from agentauth.capabilities.monitor.detector import (
    Decision,
    DetectionReport,
    StepVerdict,
    TrajectoryDetector,
)
from agentauth.capabilities.monitor.drift import CusumDrift
from agentauth.capabilities.monitor.egress_slots import egress_templates_for_tools
from agentauth.capabilities.monitor.entailment import (
    EntailmentAdvisory,
    assess_plan_entailment,
    content_delta_vs_reference,
    deterministic_content_reasons,
    llm_entailment_judge,
    write_preferring_samples,
)
from agentauth.capabilities.monitor.envelope import TypedGoalEnvelope
from agentauth.capabilities.monitor.generation import (
    CompiledEnvelope,
    Planner,
    StructuredIntentPlanner,
    compile_envelope,
    verify_plan,
)
from agentauth.capabilities.monitor.intent_advisory import (
    AdvisoryVerdict,
    assess_intent_advisory,
)
from agentauth.capabilities.monitor.intent_envelope import (
    INTENT_ENVELOPE_SCHEMA,
    CallTemplate,
    Deviation,
    IntentConformance,
    IntentEnvelope,
    ParameterSlot,
    Phase,
    SlotSource,
    sign_intent_envelope,
    verify_intent_envelope,
)
from agentauth.capabilities.monitor.llm_clients import (
    default_entailment_judge,
    make_chat_client,
)
from agentauth.capabilities.monitor.ontology import ToolOntology, ToolSpec
from agentauth.capabilities.monitor.provenance import TaintTracker, TaintVerdict
from agentauth.capabilities.monitor.reachability import EnvelopeDeparture, PathEnvelope
from agentauth.capabilities.monitor.scoring import NGramScorer, SequenceScorer
from agentauth.capabilities.monitor.sealed_plan import (
    SealedPlanConstraints,
    check_sealed_plan,
    compile_sealed_plan,
    content_digest,
    extract_callees,
    extract_destinations,
    is_secret_path,
)
from agentauth.capabilities.monitor.symbolic_planner import SymbolicPlanner, fact_landmarks
from agentauth.capabilities.monitor.twin_corridor import (
    TwinStructuralVerdict,
    assess_twin_structural,
    intent_from_reference,
)

__all__ = [
    "INTENT_ENVELOPE_SCHEMA",
    "Action",
    "AdvisoryVerdict",
    "AmlAnalytics",
    "AmlVerdict",
    "CallTemplate",
    "CompiledEnvelope",
    "ConformalCalibrator",
    "ConsequenceLevel",
    "ContextItem",
    "CusumDrift",
    "Decision",
    "DetectionReport",
    "Deviation",
    "EntailmentAdvisory",
    "EnvelopeDeparture",
    "IntentConformance",
    "IntentEnvelope",
    "MondrianConformal",
    "NGramScorer",
    "NodeKind",
    "ParameterSlot",
    "PathEnvelope",
    "Phase",
    "PlanNode",
    "Planner",
    "SealedPlanConstraints",
    "SequenceScorer",
    "SlotSource",
    "StepVerdict",
    "StructuredIntentPlanner",
    "SymbolicPlanner",
    "TaintTracker",
    "TaintVerdict",
    "ToolOntology",
    "ToolSpec",
    "Trajectory",
    "TrajectoryDetector",
    "TrustLevel",
    "TwinStructuralVerdict",
    "TypedGoalEnvelope",
    "action_token",
    "assess_intent_advisory",
    "assess_plan_entailment",
    "assess_twin_structural",
    "check_declaration_against_goal",
    "check_sealed_plan",
    "classify_consequence",
    "compile_envelope",
    "compile_sealed_plan",
    "content_delta_vs_reference",
    "content_digest",
    "default_entailment_judge",
    "deterministic_content_reasons",
    "egress_templates_for_tools",
    "envelope_from_tree",
    "extract_callees",
    "extract_destinations",
    "fact_landmarks",
    "fine_action_token",
    "intent_from_reference",
    "is_consequential",
    "is_secret_path",
    "leaf",
    "linearize",
    "llm_entailment_judge",
    "loop",
    "make_chat_client",
    "seal_declaration",
    "selector",
    "sequence",
    "sign_intent_envelope",
    "trajectory_tokens",
    "verify_intent_envelope",
    "verify_plan",
    "write_preferring_samples",
]
