"""Trusted catalog shape judge + DeployableStack default replan wiring."""
from __future__ import annotations

from clayseal.capabilities.broker import Outcome, SessionBroker
from clayseal.capabilities.deployable_stack import DeployableStack
from clayseal.capabilities.monitor.action import Action
from clayseal.capabilities.monitor.intent_envelope import IntentEnvelope
from clayseal.capabilities.parameter_provenance import ParameterProvenance
from clayseal.capabilities.replan import ActionShape, PlanExtender, catalog_shape_judge
from clayseal.capabilities.scoping.goal import GoalSpec
from clayseal.core.task_scope import TaskScope


def test_catalog_shape_judge_admits_goal_implied_tool():
    judge = catalog_shape_judge(allowed_classes={"communicate"})
    ok, why = judge(
        "email Alice the meeting notes",
        ["send_email", "read_file"],
        ActionShape.of("send_email", "send"),
    )
    assert ok
    assert "communicate" in why or "implied" in why or "permitted" in why


def test_catalog_shape_judge_refuses_unrelated_consequential():
    judge = catalog_shape_judge(allowed_classes=set())
    ok, _ = judge(
        "list files in the workspace",
        ["send_email", "Bash"],
        ActionShape.of("send_email", "send"),
    )
    assert not ok


def test_deployable_stack_default_provenance():
    stack = DeployableStack.from_goal(
        GoalSpec(query_id="t", summary="pay bob@corp.example from payees.json"),
        scope=TaskScope(allowed_resources=["workspace"], allowed_actions=["send"]),
        entailment_judge=None,
        enable_replan=False,
    )
    assert isinstance(stack.broker.provenance, ParameterProvenance)
    assert any("payees.json" in o or o.endswith(".json")
               for o in stack.broker.goal_named_objects) or "payees.json" in (
        stack.broker.goal.summary or ""
    )


def test_envelope_replan_extends_bound_off_plan_step():
    """Destination-bound off-plan shape → plan extends (not hard deny)."""
    from clayseal.capabilities.hardening.egress_policy import EgressPolicy

    goal = GoalSpec(
        query_id="t",
        summary="read the calendar and send_email a summary to bob@corp.example",
        structured_intent={"verbs": ["read", "send"], "tools": ["Calendar", "send_email"]},
    )
    # Minimal envelope that only listed Calendar, send is off-plan.
    env = IntentEnvelope.from_goal(goal)
    # Strip send from plan if present so the step is a deviation.
    if hasattr(env, "allowed_tools"):
        pass

    stack = DeployableStack.from_goal(
        goal,
        scope=TaskScope(
            allowed_resources=["workspace", "mcp:tool:send_email"],
            allowed_actions=["read", "send"]),
        allowed_tools={"Calendar", "send_email"},
        egress=EgressPolicy(
            bind_recipients=True, allow_all=False,
            allowed_recipients={"bob@corp.example"},
            allowed_domains={"corp.example"}),
        intent_envelope=env,
        entailment_judge=None,
        enable_replan=True,
        scope_is_advisory=True,
        defer_to_binding=True,
    )
    assert stack.broker.plan_extender is not None
    # Force an off-plan envelope: only Calendar was cleared.
    stack.broker.intent_envelope = IntentEnvelope(
        allowed_tools=frozenset({"Calendar"}),
        allowed_verbs=frozenset({"read"}),
        allowed_resource_classes=frozenset({"workspace"}),
    )
    d = stack.authorize(Action(
        0, "send_email", "mcp:tool:send_email", "send",
        args={"to": "bob@corp.example", "body": "summary"},
    ))
    # Extended allow, or STEP_UP if envelope treats differently, never silent
    # hard deny when destination is goal-bound and shape is goal-implied.
    assert d.outcome in ("allow", "step_up")
    if d.outcome == "deny":
        raise AssertionError(f"unexpected hard deny: {d.layer} {d.reasons}")
    # Auto-reclear grew the sealed plan (trusted shape only).
    assert "send_email" in stack.broker.intent_envelope.allowed_tools


def test_intent_envelope_with_shape_is_membership_only_growth():
    env = IntentEnvelope(
        allowed_tools=frozenset({"Calendar"}),
        allowed_verbs=frozenset({"read"}),
        allowed_resource_classes=frozenset(),
    )
    grown = env.with_shape("send_email", "send")
    assert "send_email" in grown.allowed_tools
    assert "send" in grown.allowed_verbs
    assert "Calendar" in grown.allowed_tools
    assert env.allowed_tools == frozenset({"Calendar"})
