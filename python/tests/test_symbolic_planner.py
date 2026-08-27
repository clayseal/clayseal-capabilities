"""Phase C2: symbolic diverse-planner. Derives the plan from the ontology by
landmark analysis, deterministic, sound, non-injectable, multi-modal aware."""
from __future__ import annotations

from clayseal.core.signing import generate_keypair
from clayseal.core.task_scope import TaskScope
from clayseal.capabilities.broker import Outcome, SessionBroker
from clayseal.capabilities.monitor import (
    Action,
    SymbolicPlanner,
    Trajectory,
    compile_envelope,
    fact_landmarks,
)
from clayseal.capabilities.monitor.ontology import ToolOntology
from clayseal.capabilities.scoping.goal import GoalSpec


def _goal(ontology, gc=("deployed",), tools=None) -> GoalSpec:
    tools = tools or [s["tool"] for s in ontology]
    return GoalSpec(
        query_id="deploy", summary="ship it",
        allow_resources=[f"mcp:tool:{t}" for t in tools],
        structured_intent={
            "initial_facts": ["source"], "goal_conditions": list(gc), "ontology": ontology,
        },
    )


_SINGLE = [
    {"tool": "build", "preconditions": ["source"], "establishes": ["artifact"]},
    {"tool": "run_tests", "preconditions": ["artifact"], "establishes": ["tested"]},
    {"tool": "deploy", "preconditions": ["artifact", "tested"], "establishes": ["deployed"]},
]

# Two legitimate ways to deploy: neither is individually required (multi-modal).
_MULTI = _SINGLE[:2] + [
    {"tool": "deploy_canary", "preconditions": ["artifact", "tested"], "establishes": ["deployed"]},
    {"tool": "deploy_bluegreen", "preconditions": ["artifact", "tested"], "establishes": ["deployed"]},
]


def _a(step, tool): return Action(step, tool, f"mcp:tool:{tool}", "execute")


def test_landmarks_backchain_from_goal():
    specs = ToolOntology.from_dict(_SINGLE).specs
    lms = fact_landmarks(specs, {"source"}, {"deployed"})
    assert {"deployed", "artifact", "tested"} <= lms


def test_single_path_derives_ordered_phases():
    env = SymbolicPlanner().plan(_goal(_SINGLE))
    # Three ordered required phases: build -> run_tests -> deploy.
    assert len(env.phases) == 3
    assert env.phases[0].tools == frozenset({"build"})
    assert env.phases[-1].tools == frozenset({"deploy"})
    # The benign plan conforms; deploying first is out of order.
    goal = _goal(_SINGLE)
    ok_traj = Trajectory(goal=goal,
                         actions=[_a(0, "build"), _a(1, "run_tests"), _a(2, "deploy")])
    assert env.assess(ok_traj).conforms
    bad = Trajectory(goal=goal, actions=[_a(0, "deploy")])
    assert not env.assess(bad).conforms


def test_multimodal_neither_deploy_tool_is_forced():
    env = SymbolicPlanner().plan(_goal(_MULTI))
    goal = _goal(_MULTI)
    # The final phase admits EITHER deploy tool (disjunctive landmark).
    final = env.phases[-1].tools
    assert final == frozenset({"deploy_canary", "deploy_bluegreen"})
    for deploy in ("deploy_canary", "deploy_bluegreen"):
        traj = Trajectory(goal=goal, actions=[_a(0, "build"), _a(1, "run_tests"), _a(2, deploy)])
        assert env.assess(traj).conforms, deploy


def test_symbolic_plan_compiles_and_signs():
    key = generate_keypair()
    compiled = compile_envelope(_goal(_SINGLE), planner=SymbolicPlanner(), key=key)
    assert compiled.satisfiable and compiled.sealed
    assert len(compiled.envelope.phases) == 3


def test_symbolic_envelope_enforced_by_broker_cold():
    goal = _goal(_MULTI)
    compiled = compile_envelope(goal, planner=SymbolicPlanner(), key=generate_keypair())
    scope = TaskScope(
        allowed_resources=[f"mcp:tool:{t}" for t in
                          ("build", "run_tests", "deploy_canary", "deploy_bluegreen")],
        allowed_actions=["execute"],
    )
    broker = SessionBroker(goal=goal, scope=scope, intent_envelope=compiled.envelope, detector=None)
    # Deploy before building is out of order and consequential -> denied, no history.
    assert broker.authorize(_a(0, "deploy_canary")).outcome is Outcome.DENY


def test_falls_back_without_domain_model():
    goal = GoalSpec(query_id="q", summary="open ended",
                    allow_resources=["mcp:tool:search"],
                    structured_intent={"tools": ["search"], "verbs": ["read"]})
    env = SymbolicPlanner().plan(goal)  # no ontology/goal_conditions
    assert "search" in env.allowed_tools and env.phases == ()
