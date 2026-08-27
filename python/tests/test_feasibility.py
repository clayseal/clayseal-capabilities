"""Phase B: feasibility (is the goal still reachable?) via delete-aware
reachability over a tool ontology. The coding-agent mission-break, caught cold."""
from __future__ import annotations

from clayseal.core.task_scope import TaskScope
from clayseal.capabilities.broker import Outcome, SessionBroker
from clayseal.capabilities.monitor import (
    Action,
    IntentEnvelope,
    ToolOntology,
    Trajectory,
)
from clayseal.capabilities.scoping.goal import GoalSpec


# A deploy task: build -> test -> deploy. Deleting the build is individually
# plausible (agents delete files) but destroys a precondition of deploy, so the
# goal "deployed" can never be reached afterwards.
_ONTOLOGY = ToolOntology.from_dict([
    {"tool": "build", "preconditions": ["source"], "establishes": ["artifact"]},
    {"tool": "run_tests", "preconditions": ["artifact"], "establishes": ["tested"]},
    {"tool": "deploy", "preconditions": ["artifact", "tested"], "establishes": ["deployed"]},
    {"tool": "delete_build", "destroys": ["artifact"], "reversible": False},
])


def _goal() -> GoalSpec:
    return GoalSpec(
        query_id="deploy-flow",
        summary="build, test, and deploy the service",
        allow_resources=["mcp:tool:build", "mcp:tool:run_tests",
                         "mcp:tool:deploy", "mcp:tool:delete_build"],
        structured_intent={
            "kind": "deploy-flow",
            "verbs": ["execute", "write", "delete"],
            "initial_facts": ["source"],
            "goal_conditions": ["deployed"],
            "ontology": _ONTOLOGY.to_dict(),
        },
    )


def _a(step, tool, verb): return Action(step, tool, f"mcp:tool:{tool}", verb)


def test_feasibility_holds_for_the_benign_plan():
    env = IntentEnvelope.from_goal(_goal())
    traj = Trajectory(goal=_goal(), actions=[
        _a(0, "build", "execute"), _a(1, "run_tests", "execute"), _a(2, "deploy", "write")])
    ok, _ = env.feasible(traj)
    assert ok


def test_irreversible_action_makes_goal_unreachable_no_history():
    env = IntentEnvelope.from_goal(_goal())
    # Delete the build after building: 'deployed' can no longer be reached.
    traj = Trajectory(goal=_goal(), actions=[
        _a(0, "build", "execute"), _a(1, "delete_build", "delete")])
    ok, reason = env.feasible(traj)
    assert not ok and "deployed" in reason


def _broker() -> SessionBroker:
    goal = _goal()
    scope = TaskScope(
        allowed_resources=[f"mcp:tool:{t}" for t in ("build", "run_tests", "deploy", "delete_build")],
        allowed_actions=["execute", "write", "delete"],
    )
    return SessionBroker(goal=goal, scope=scope,
                         intent_envelope=IntentEnvelope.from_goal(goal), detector=None)


def test_broker_denies_mission_breaking_action_cold():
    # The floor allows delete_build (in scope); only feasibility catches that it
    # makes the goal unreachable, with zero history. Deletion is consequential,
    # so the two-signal gate blocks it.
    broker = _broker()
    assert broker.authorize(_a(0, "build", "execute")).outcome is Outcome.ALLOW
    d = broker.authorize(_a(1, "delete_build", "delete"))
    assert d.outcome is Outcome.DENY and d.layer == "intent-envelope"
    assert "deployed" in d.reasons[0]


def test_broker_allows_graceful_replan():
    # A legitimate deviation (re-running tests, an extra build) keeps the goal
    # reachable, so feasibility must not block it.
    broker = _broker()
    for a in [_a(0, "build", "execute"), _a(1, "run_tests", "execute"),
              _a(2, "run_tests", "execute"),   # re-run: off golden path, still feasible
              _a(3, "deploy", "write")]:
        assert broker.authorize(a).outcome is Outcome.ALLOW, a.tool


def test_envelope_roundtrips_and_signs():
    from clayseal.core.signing import generate_keypair
    from clayseal.capabilities.monitor import (
        sign_intent_envelope, verify_intent_envelope, IntentEnvelope)

    env = IntentEnvelope.from_goal(_goal())
    # to_dict/from_dict preserves the plan and the feasibility model.
    rebuilt = IntentEnvelope.from_dict(env.to_dict())
    assert rebuilt.goal_conditions == env.goal_conditions
    assert rebuilt.ontology is not None and "delete_build" in rebuilt.ontology.specs

    key = generate_keypair()
    signed = sign_intent_envelope(env, key=key)
    ok, err = verify_intent_envelope(signed, trusted_keys={key.public_key_hex})
    assert ok, err
    # Tamper the sealed plan -> verification fails.
    signed["document"]["goal_conditions"] = ["nothing"]
    bad, why = verify_intent_envelope(signed)
    assert not bad and "invalid" in (why or "")
    # An untrusted signer is rejected under pinning.
    other = generate_keypair()
    ok2, why2 = verify_intent_envelope(sign_intent_envelope(env, key=other),
                                       trusted_keys={key.public_key_hex})
    assert not ok2 and "trusted" in (why2 or "")
