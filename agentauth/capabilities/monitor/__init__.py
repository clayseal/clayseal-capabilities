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
    classify as classify_consequence,
    is_consequential,
)
from agentauth.capabilities.monitor.drift import CusumDrift
from agentauth.capabilities.monitor.generation import (
    CompiledEnvelope,
    Planner,
    StructuredIntentPlanner,
    compile_envelope,
    verify_plan,
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
from agentauth.capabilities.monitor.ontology import ToolOntology, ToolSpec
from agentauth.capabilities.monitor.reachability import EnvelopeDeparture, PathEnvelope
from agentauth.capabilities.monitor.symbolic_planner import SymbolicPlanner, fact_landmarks
from agentauth.capabilities.monitor.sealed_plan import (
    SealedPlanConstraints,
    check_sealed_plan,
    compile_sealed_plan,
    extract_callees,
    extract_destinations,
    content_digest,
    is_secret_path,
)
from agentauth.capabilities.monitor.twin_corridor import (
    TwinStructuralVerdict,
    assess_twin_structural,
    intent_from_reference,
)
from agentauth.capabilities.monitor.detector import (
    Decision,
    DetectionReport,
    StepVerdict,
    TrajectoryDetector,
)
from agentauth.capabilities.monitor.envelope import TypedGoalEnvelope
from agentauth.capabilities.monitor.provenance import TaintTracker, TaintVerdict
from agentauth.capabilities.monitor.scoring import NGramScorer, SequenceScorer

__all__ = [
    "Action",
    "AmlAnalytics",
    "AmlVerdict",
    "INTENT_ENVELOPE_SCHEMA",
    "CallTemplate",
    "CompiledEnvelope",
    "ConformalCalibrator",
    "ConsequenceLevel",
    "ContextItem",
    "CusumDrift",
    "Planner",
    "StructuredIntentPlanner",
    "SymbolicPlanner",
    "compile_envelope",
    "fact_landmarks",
    "verify_plan",
    "Decision",
    "Deviation",
    "IntentConformance",
    "IntentEnvelope",
    "ParameterSlot",
    "Phase",
    "SlotSource",    "ToolOntology",
    "ToolSpec",
    "classify_consequence",
    "is_consequential",
    "sign_intent_envelope",
    "verify_intent_envelope",
    "DetectionReport",
    "EnvelopeDeparture",
    "MondrianConformal",
    "NGramScorer",
    "NodeKind",
    "PlanNode",
    "envelope_from_tree",
    "leaf",
    "linearize",
    "loop",
    "selector",
    "sequence",
    "PathEnvelope",
    "SequenceScorer",
    "StepVerdict",
    "TaintTracker",
    "TaintVerdict",
    "Trajectory",
    "TrajectoryDetector",
    "TwinStructuralVerdict",
    "assess_twin_structural",
    "intent_from_reference",
    "SealedPlanConstraints",
    "compile_sealed_plan",
    "check_sealed_plan",
    "extract_callees",
    "extract_destinations",
    "content_digest",
    "is_secret_path",
    "TrustLevel",
    "TypedGoalEnvelope",
    "action_token",
    "fine_action_token",
    "trajectory_tokens",
]
