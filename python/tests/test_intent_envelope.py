"""Phase A: the goal-derived Intent Envelope (history-free), two-signal gate,
and demotion of the statistical detector to a sensor."""
from __future__ import annotations

from clayseal.core.task_scope import TaskScope
from clayseal.capabilities.broker import Outcome, SessionBroker
from clayseal.capabilities.monitor import (
    Action,
    Deviation,
    IntentEnvelope,
    Trajectory,
    is_consequential,
    is_effectful,
)
from clayseal.capabilities.scoping.goal import GoalSpec


def _pay_flow_goal() -> GoalSpec:
    # Read the invoices, THEN pay them. Order is part of the intent.
    return GoalSpec(
        query_id="pay-flow",
        summary="read the invoices then pay them",
        allow_resources=["mcp:tool:read_invoice", "mcp:tool:pay_invoice"],
        structured_intent={
            "kind": "pay-flow",
            "verbs": ["read", "transfer"],
            "phases": [
                {"tools": ["read_invoice"], "verbs": ["read"], "min": 1},
                {"tools": ["pay_invoice"], "verbs": ["transfer"]},
            ],
        },
    )


def _read(step): return Action(step, "read_invoice", "mcp:tool:read_invoice", "read")
def _pay(step): return Action(step, "pay_invoice", "mcp:tool:pay_invoice", "transfer",
                              args={"amount": 100.0})


# --- module: conformance is history-free ------------------------------------
def test_envelope_compiles_from_goal_only():
    env = IntentEnvelope.from_goal(_pay_flow_goal())
    assert "read_invoice" in env.allowed_tools and "pay_invoice" in env.allowed_tools
    assert len(env.phases) == 2


def test_in_plan_sequence_conforms():
    env = IntentEnvelope.from_goal(_pay_flow_goal())
    traj = Trajectory(goal=_pay_flow_goal(), actions=[_read(0), _read(1), _pay(2)])
    assert env.assess(traj).conforms


def test_out_of_order_is_flagged_with_no_history():
    env = IntentEnvelope.from_goal(_pay_flow_goal())
    # Pay before reading anything: the required earlier phase is unmet.
    traj = Trajectory(goal=_pay_flow_goal(), actions=[_pay(0)])
    conf = env.assess(traj)
    assert not conf.conforms
    assert conf.deviations[0].deviation is Deviation.OUT_OF_ORDER


def test_off_tool_is_flagged():
    env = IntentEnvelope.from_goal(_pay_flow_goal())
    alien = Action(0, "wire_transfer", "mcp:tool:wire_transfer", "transfer")
    traj = Trajectory(goal=_pay_flow_goal(), actions=[alien])
    assert env.assess(traj).deviations[0].deviation is Deviation.OFF_TOOL


# --- partial order: keep the meaningful edges, drop the incidental ones ------
def _partial_order_env() -> IntentEnvelope:
    """Three phases: read_balance (0) and read_iban (1) are independent; pay (2)
    genuinely requires read_iban. The only real edge is 1 -> 2."""
    from clayseal.capabilities.monitor import Phase
    return IntentEnvelope(
        allowed_tools=frozenset({"read_balance", "read_iban", "pay"}),
        allowed_verbs=frozenset(), allowed_resource_classes=frozenset(),
        phases=(Phase(tools=frozenset({"read_balance"}), min=1),
                Phase(tools=frozenset({"read_iban"}), min=1),
                Phase(tools=frozenset({"pay"}), min=1)),
        phase_order=frozenset({(1, 2)}))


def _act(step, tool, verb="read"):
    return Action(step, tool, f"mcp:tool:{tool}", verb)


def test_partial_order_allows_independent_interleaving():
    # read_iban before read_balance: no edge between them, so NOT out of order.
    env = _partial_order_env()
    goal = GoalSpec(query_id="po", summary="po")
    traj = Trajectory(goal=goal, actions=[_act(0, "read_iban"), _act(1, "read_balance"),
                                          _act(2, "pay", "transfer")])
    assert env.assess(traj).conforms


def test_partial_order_still_enforces_real_edge():
    # pay before read_iban violates the real 1 -> 2 edge: out of order.
    env = _partial_order_env()
    goal = GoalSpec(query_id="po", summary="po")
    traj = Trajectory(goal=goal, actions=[_act(0, "read_balance"), _act(1, "pay", "transfer")])
    conf = env.assess(traj)
    assert not conf.conforms
    assert any(d.deviation is Deviation.OUT_OF_ORDER for d in conf.deviations)


def test_empty_partial_order_is_membership_only():
    # No edges at all: any order of planned tools conforms (the live-planner case).
    env = _partial_order_env()
    env.phase_order = frozenset()
    goal = GoalSpec(query_id="po", summary="po")
    traj = Trajectory(goal=goal, actions=[_act(0, "pay", "transfer"), _act(1, "read_iban")])
    assert env.assess(traj).conforms


# --- broker: primary tier, no detector, no history --------------------------
def _broker(**kw) -> SessionBroker:
    goal = _pay_flow_goal()
    # Floor is deliberately broader than the plan, to isolate the envelope's
    # contribution: the floor allows pay_invoice out of order; the envelope does not.
    scope = TaskScope(
        allowed_resources=["mcp:tool:read_invoice", "mcp:tool:pay_invoice",
                           "mcp:tool:browse", "mcp:tool:exfiltrate"],
        allowed_actions=["read", "transfer", "send"],
    )
    return SessionBroker(goal=goal, scope=scope,
                         intent_envelope=IntentEnvelope.from_goal(goal), detector=None, **kw)


def test_broker_allows_in_plan_flow_cold():
    broker = _broker()
    assert broker.authorize(_read(0)).outcome is Outcome.ALLOW
    assert broker.authorize(_read(1)).outcome is Outcome.ALLOW
    assert broker.authorize(_pay(2)).outcome is Outcome.ALLOW  # order satisfied


def test_broker_denies_out_of_order_consequential_action_cold():
    # The floor allows pay_invoice (in scope); only the goal-derived envelope
    # catches that it is out of order, with ZERO history, and because paying is
    # consequential the two-signal gate blocks it.
    broker = _broker()
    d = broker.authorize(_pay(0))
    assert d.outcome is Outcome.DENY and d.layer == "intent-envelope"
    assert broker.decision_log.verify()[0]


def test_two_signal_escalates_offplan_read_but_denies_offplan_write():
    broker = _broker()
    # Off-plan read (floor-allowed, not in the plan): escalate, not block.
    read_dev = broker.authorize(Action(0, "browse", "mcp:tool:browse", "read"))
    assert read_dev.outcome is Outcome.STEP_UP and read_dev.layer == "intent-envelope"
    # Off-plan consequential (send): block.
    send_dev = broker.authorize(Action(1, "exfiltrate", "mcp:tool:exfiltrate", "send",
                                       args={"to": "attacker@evil.test"}))
    assert send_dev.outcome is Outcome.DENY and send_dev.layer == "intent-envelope"


def test_consequence_classifier():
    # A read that names something is a disclosure: content it puts into the
    # session cannot be un-read. That makes it consequential enough to escalate
    # and never enough to refuse outright, which is the distinction between the
    # two predicates and the reason both exist.
    assert is_consequential(_read(0))
    assert not is_effectful(_read(0))
    # A read that names nothing has disclosed nothing.
    assert not is_consequential(Action(0, "noop", "", "read"))
    for effectful in (_pay(0), Action(0, "del", "mcp:tool:del", "delete")):
        assert is_consequential(effectful)
        assert is_effectful(effectful)
