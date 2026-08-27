"""The seam a workload actually needs: "in our shop X is also forbidden".

Every other knob on `from_goal` tunes behaviour someone else chose. This is
where a deployment adds its own rule without forking the gateway.
"""
from __future__ import annotations

import pytest

from clayseal.capabilities.deployable_stack import DeployableStack
from clayseal.capabilities.monitor.action import Action
from clayseal.capabilities.scoping.goal import GoalSpec
from clayseal.capabilities.session_rules import SessionRuleHit
from clayseal.core.task_scope import TaskScope

GOAL = GoalSpec(query_id="q", summary="email the summary")
SCOPE = TaskScope(allowed_resources=["workspace"],
                  allowed_actions=["send", "write"])


def _stack(**kw):
    return DeployableStack.from_goal(GOAL, scope=SCOPE, entailment_judge=None,
                                     session_rules=True, **kw)


def _send(to):
    return Action(0, "send_email", "workspace", "send", args={"to": to})


def no_competitors(action, session, *, goal_summary, egress_verbs):
    if "competitor.test" in str(action.args or {}):
        return SessionRuleHit("house-rules", "destination is a competitor domain")
    return None


def test_a_house_rule_fires_and_stamps_its_own_layer():
    decision = _stack(house_rules=(no_competitors,)).authorize(
        _send("leaks@competitor.test"))
    assert decision.outcome == "step_up"
    assert decision.layer == "house-rules"
    assert "competitor" in " ".join(decision.reasons)


def test_it_does_not_fire_on_ordinary_traffic():
    assert _stack(house_rules=(no_competitors,)).authorize(
        _send("ops@acme-internal.com")).outcome == "allow"


def test_a_house_rule_steps_up_and_never_denies():
    """Same contract as the built-in pack.

    A rule written against one workload has not been measured against the
    traffic it will refuse. A step-up halts an autonomous attacker just as hard
    and leaves a person able to say yes.
    """
    def always(action, session, *, goal_summary, egress_verbs):
        return SessionRuleHit("house-rules", "always fires")

    assert _stack(house_rules=(always,)).authorize(
        _send("ops@acme-internal.com")).outcome == "step_up"


def test_a_rule_that_raises_is_skipped_not_fatal():
    """A gateway that stops authorizing because somebody's regex threw is
    worse than one that misses that rule. The failure is counted, not silent."""
    from clayseal.capabilities import session_rules

    def broken(action, session, *, goal_summary, egress_verbs):
        raise ValueError("bad rule")

    session_rules.RULE_FAILURES.clear()
    decision = _stack(house_rules=(broken, no_competitors)).authorize(
        _send("leaks@competitor.test"))
    # The broken rule did not stop the good one behind it.
    assert decision.outcome == "step_up"
    assert decision.layer == "house-rules"
    assert session_rules.RULE_FAILURES.get("broken") == 1


def test_house_rules_run_after_the_shipped_ones():
    """A house rule must not be able to mask a rule that ships."""
    import inspect

    from clayseal.capabilities import session_rules

    body = inspect.getsource(session_rules.check)
    assert body.index("_sed_line_drift") < body.index("_check_extra")


def test_no_house_rules_is_the_default():
    assert _stack().broker.house_rules == ()
