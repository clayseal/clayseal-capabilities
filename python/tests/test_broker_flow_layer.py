"""`FlowTracker` wired into the broker, as a STEP_UP layer.

The engine already existed and was unwired: it composes `ParameterProvenance`,
tracks content derivation across writes, and neither `SessionBroker` nor
`DeployableStack` ever constructed it. Its only consumers were two benchmark
modules.

STEP_UP rather than DENY is a measurement, not caution. `flow_window.md`: after
the write windowing the tracker refuses 0 of 1,242 real benign events and closes
the two-write split it used to miss entirely (200/200 out -> 0/200), but 22
fragments out of order still walk out in 162/200 runs and unkeyed encodings are
100/100 at every width. Sound where it fires, incomplete in what it catches.
"""
from __future__ import annotations

import pytest

from agentauth.capabilities.broker import Outcome, SessionBroker
from agentauth.capabilities.confidentiality import FlowTracker, SensitivityPolicy
from agentauth.capabilities.monitor.action import Action
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.capabilities.step_up import violation_code

SECRET = "AKIA0123456789ABCDEFQZ"
POLICY = SensitivityPolicy(sensitive=("db:customers",),
                           declassified_sinks=("mail:board",))


def _broker(**kw):
    return SessionBroker(
        goal=GoalSpec(query_id="q", summary="s", allow_resources=[]),
        flow=FlowTracker(), sensitivity=POLICY, **kw)


def _observed(broker):
    broker.observe_output("read_table", SECRET,
                          structured_fields={"value": SECRET},
                          containing_object="db:customers",
                          source_path="db:customers")
    return broker


def _send(broker, body, to="mail:evil@test", step=0):
    return broker.authorize(Action(step=step, tool="send_mail", resource=to,
                                   verb="send", args={"body": body}))


def test_a_write_carrying_a_read_secret_steps_up():
    decision = _send(_observed(_broker()), SECRET)
    assert decision.outcome is Outcome.STEP_UP
    assert decision.layer == "flow"


def test_it_steps_up_rather_than_denying():
    """The load-bearing choice. A layer with known holes that refuses outright
    buys the holes nothing and costs the false blocks everything."""
    decision = _send(_observed(_broker()), SECRET)
    assert decision.outcome is not Outcome.DENY
    assert decision.step_up is not None


def test_an_unrelated_write_is_untouched():
    """0 of 1,242 real benign events refused. A layer that fires on ordinary
    traffic is the accumulator bug again."""
    decision = _send(_observed(_broker()), "ordinary status update")
    assert decision.outcome is Outcome.ALLOW


def test_a_goal_declassified_sink_is_allowed():
    decision = _send(_observed(_broker()), SECRET, to="mail:board")
    assert decision.outcome is Outcome.ALLOW


def test_nothing_fires_when_no_secret_was_read():
    """Observation is what arms the layer; without it there is nothing to carry."""
    decision = _send(_broker(), SECRET)
    assert decision.outcome is Outcome.ALLOW


def test_the_layer_is_off_when_the_policy_declares_nothing():
    """An empty policy must not silently enable a control nobody configured."""
    broker = SessionBroker(
        goal=GoalSpec(query_id="q", summary="s", allow_resources=[]),
        flow=FlowTracker(), sensitivity=SensitivityPolicy())
    assert _send(broker, SECRET).outcome is Outcome.ALLOW


def test_the_broker_works_with_no_flow_tracker_at_all():
    """Both fields default to None, so every existing caller is unaffected."""
    broker = SessionBroker(goal=GoalSpec(query_id="q", summary="s",
                                         allow_resources=[]))
    assert broker.flow is None and broker.sensitivity is None
    assert _send(broker, SECRET).outcome is Outcome.ALLOW


def test_the_flow_objection_has_a_waivable_rule_code():
    """Unclassified rules cannot be waived by design, so a new step-up path that
    forgets its code is unresolvable. This one has one."""
    assert violation_code("flow: would carry data read from db:customers") == \
        "flow.derivation"


def test_a_broken_tracker_does_not_break_authorization():
    """A gate may deny; it may not crash."""
    class Exploding:
        def observe(self, *a, **k):
            raise RuntimeError("boom")

        def check(self, **k):
            raise RuntimeError("boom")

    broker = SessionBroker(
        goal=GoalSpec(query_id="q", summary="s", allow_resources=[]),
        flow=Exploding(), sensitivity=POLICY)
    broker.observe_output("read_table", SECRET, source_path="db:customers")
    assert _send(broker, SECRET).outcome is Outcome.ALLOW
