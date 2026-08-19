"""Intent advisory: digΔ vs declaration escalates; never hard-blocks alone."""
from __future__ import annotations

from agentauth.capabilities.monitor.action import Action, Trajectory
from agentauth.capabilities.monitor.detector import Decision, TrajectoryDetector
from agentauth.capabilities.monitor.egress_slots import egress_templates_for_tools
from agentauth.capabilities.monitor.intent_advisory import assess_intent_advisory
from agentauth.capabilities.monitor.intent_envelope import IntentEnvelope
from agentauth.capabilities.scoping.goal import GoalSpec


def _traj(commands: list[str], *, summary: str = "backup weights") -> Trajectory:
    goal = GoalSpec(query_id="t", summary=summary)
    actions = [
        Action(
            step=i, tool="Bash", resource="shell", verb="execute",
            args={"command": cmd},
        )
        for i, cmd in enumerate(commands)
    ]
    return Trajectory(goal=goal, actions=actions)


def test_matching_declaration_is_quiet():
    plan = _traj(['cat > /tmp/out.txt <<EOF\nhonest\nEOF'])
    v = assess_intent_advisory(plan, declaration=plan)
    assert not v.escalate


def test_dig_delta_vs_declaration_escalates():
    plan = _traj(['cat > /tmp/out.txt <<EOF\nhonest\nEOF'])
    attack = _traj(['cat > /tmp/out.txt <<EOF\nexfil webhook\nEOF'])
    v = assess_intent_advisory(attack, declaration=plan)
    assert v.escalate
    assert any("digΔ" in r for r in v.reasons)


def test_advisory_escalates_detector_without_structural_block():
    plan = _traj(['cat > /tmp/out.txt <<EOF\nhonest\nEOF'])
    attack = _traj(['cat > /tmp/out.txt <<EOF\nexfil webhook\nEOF'])
    det = TrajectoryDetector(use_twin_reference=False, use_intent_advisory=True)
    # Unfitted detector: no conformal block; advisory still soft-escalates.
    report = det.assess(attack, reference=plan)
    assert not report.structural_block
    assert report.verdicts[-1].decision is Decision.ESCALATE


def test_egress_templates_cover_send_tools():
    templates = egress_templates_for_tools(["send_email", "read_file", "transfer_funds"])
    tools = {t.tool for t in templates}
    assert "send_email" in tools
    assert "transfer_funds" in tools
    assert "read_file" not in tools
    send = next(t for t in templates if t.tool == "send_email")
    assert any(s.name == "to" for s in send.slots)


def test_broker_slot_denies_ungrounded_send():
    from agentauth.capabilities.broker import Outcome, SessionBroker
    from agentauth.capabilities.hardening.egress_policy import EgressPolicy
    from agentauth.capabilities.parameter_provenance import ParameterProvenance
    from agentauth.core.task_scope import TaskScope

    templates = egress_templates_for_tools(["send_email"])
    env = IntentEnvelope(
        allowed_tools=frozenset(["send_email"]),
        allowed_verbs=frozenset(),
        allowed_resource_classes=frozenset(),
        call_templates=templates,
    )
    # Egress unrestricted so the slot check is what decides — not the floor.
    broker = SessionBroker(
        goal=GoalSpec(query_id="t", summary="summarise inbox"),
        scope=TaskScope(
            allowed_resources=["mcp:tool:send_email"],
            allowed_actions=["send"]),
        egress=EgressPolicy(allow_all=True),
        intent_envelope=env,
        provenance=ParameterProvenance(),
    )
    d = broker.authorize(Action(
        step=0, tool="send_email", resource="mcp:tool:send_email",
        verb="send", args={"to": "attacker@evil.test", "body": "hi"}))
    assert d.outcome is Outcome.DENY
    assert any("slot" in r.lower() or "observation" in r.lower() for r in d.reasons)


def test_broker_slot_allows_goal_seeded_recipient():
    from agentauth.capabilities.broker import Outcome, SessionBroker
    from agentauth.capabilities.hardening.egress_policy import EgressPolicy
    from agentauth.capabilities.parameter_provenance import ParameterProvenance
    from agentauth.core.task_scope import TaskScope

    templates = egress_templates_for_tools(["send_email"])
    env = IntentEnvelope(
        allowed_tools=frozenset(["send_email"]),
        allowed_verbs=frozenset(),
        allowed_resource_classes=frozenset(),
        call_templates=templates,
    )
    broker = SessionBroker(
        goal=GoalSpec(
            query_id="t",
            summary="email the receipt to bob@corp.example"),
        scope=TaskScope(
            allowed_resources=["mcp:tool:send_email"],
            allowed_actions=["send"]),
        egress=EgressPolicy(allow_all=True),
        intent_envelope=env,
        provenance=ParameterProvenance(),
    )
    d = broker.authorize(Action(
        step=0, tool="send_email", resource="mcp:tool:send_email",
        verb="send", args={"to": "bob@corp.example", "body": "receipt"}))
    assert d.outcome is Outcome.ALLOW
