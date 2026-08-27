"""Phase C1: envelope generation, plan, ground against the ontology, sign.

The grounding step is the point: a coherent plan seals, an incoherent plan (a
goal the tools cannot reach) is caught and never sealed, so a hallucinated plan
cannot become the enforced envelope.
"""
from __future__ import annotations

from clayseal.core.signing import generate_keypair
from clayseal.capabilities.broker import Outcome, SessionBroker
from clayseal.core.task_scope import TaskScope
from clayseal.capabilities.monitor import (
    Action,
    IntentEnvelope,
    Planner,
    StructuredIntentPlanner,
    ToolOntology,
    compile_envelope,
    verify_plan,
    verify_intent_envelope,
)
from clayseal.capabilities.scoping.goal import GoalSpec

_ONTOLOGY = [
    {"tool": "build", "preconditions": ["source"], "establishes": ["artifact"]},
    {"tool": "run_tests", "preconditions": ["artifact"], "establishes": ["tested"]},
    {"tool": "deploy", "preconditions": ["artifact", "tested"], "establishes": ["deployed"]},
]


def _deploy_goal(goal_conditions=("deployed",), ontology=_ONTOLOGY) -> GoalSpec:
    return GoalSpec(
        query_id="deploy",
        summary="build test deploy",
        allow_resources=["mcp:tool:build", "mcp:tool:run_tests", "mcp:tool:deploy"],
        structured_intent={
            "kind": "deploy",
            "verbs": ["execute", "write"],
            "phases": [
                {"tools": ["build"], "verbs": ["execute"], "min": 1},
                {"tools": ["run_tests"], "verbs": ["execute"], "min": 1},
                {"tools": ["deploy"], "verbs": ["write"]},
            ],
            "initial_facts": ["source"],
            "goal_conditions": list(goal_conditions),
            "ontology": ontology,
        },
    )


def test_structured_intent_planner_reads_only_the_goal():
    planner = StructuredIntentPlanner()
    assert isinstance(planner, Planner)
    env = planner.plan(_deploy_goal())
    assert "deploy" in env.allowed_tools and len(env.phases) == 3


def test_coherent_plan_verifies_and_seals():
    key = generate_keypair()
    compiled = compile_envelope(_deploy_goal(), key=key)
    assert compiled.satisfiable and compiled.sealed
    ok, _ = verify_intent_envelope(compiled.signed, trusted_keys={key.public_key_hex})
    assert ok


def test_incoherent_plan_is_caught_and_not_sealed():
    # Goal wants "published", but no tool establishes it: the plan is unreachable.
    key = generate_keypair()
    compiled = compile_envelope(_deploy_goal(goal_conditions=("published",)), key=key)
    assert not compiled.satisfiable
    assert compiled.signed is None  # a hallucinated/incoherent plan is never sealed
    assert any("unsatisfiable" in i for i in compiled.issues)


def test_verify_flags_tool_with_unmeetable_precondition():
    goal = _deploy_goal(ontology=_ONTOLOGY + [
        {"tool": "sign_release", "preconditions": ["notarized"], "establishes": ["signed_rel"]},
    ])
    env = IntentEnvelope.from_goal(goal, ontology=ToolOntology.from_dict(goal.structured_intent["ontology"]))
    _, issues = verify_plan(env)
    assert any("notarized" in i for i in issues)


def test_pluggable_planner_seam():
    # Demonstrates the C2 seam: any object with plan(goal)->IntentEnvelope works.
    class FixedPlanner:
        name = "fixed"
        def plan(self, goal):
            return IntentEnvelope.from_goal(goal)

    compiled = compile_envelope(_deploy_goal(), planner=FixedPlanner())
    assert compiled.satisfiable and compiled.envelope.phases


def test_compiled_envelope_enforces_at_runtime_cold():
    # End to end: compile a signed envelope, then a broker enforces it with no
    # history. An out-of-order deploy (before build) is denied.
    goal = _deploy_goal()
    compiled = compile_envelope(goal, key=generate_keypair())
    scope = TaskScope(
        allowed_resources=[f"mcp:tool:{t}" for t in ("build", "run_tests", "deploy")],
        allowed_actions=["execute", "write"],
    )
    broker = SessionBroker(goal=goal, scope=scope, intent_envelope=compiled.envelope, detector=None)
    d = broker.authorize(Action(0, "deploy", "mcp:tool:deploy", "write"))
    assert d.outcome is Outcome.DENY and d.layer == "intent-envelope"
