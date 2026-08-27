"""A deployment should pick a posture, not fourteen booleans.

`DeployableStack.from_goal` takes fourteen switches that materially change the
security posture, and one of them is a measured NEGATIVE result kept so the
finding reproduces. Nothing distinguished the one you must never enable from the
thirteen you may, and nothing recorded which configuration a published number
came from.

These tests hold the properties that make a profile worth having: it is
reviewable (every departure carries its reason), it cannot be overridden
silently, and it cannot enable a known hazard by accident.
"""
from __future__ import annotations

import dataclasses

import pytest

from agentauth.capabilities.profiles import (
    AUTONOMOUS,
    BENCHMARK,
    HAZARDS,
    PROFILES,
    SUPERVISED,
    get_profile,
)
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.core.task_scope import TaskScope

GOAL = GoalSpec(query_id="q", summary="pay the approved invoices")
SCOPE = TaskScope(
    allowed_resources=["in-scope"], allowed_actions=["read", "write", "send"]
)


def build(profile):
    return profile.build(GOAL, scope=SCOPE, entailment_judge=None)


# --------------------------------------------------------------------------- #
# The postures differ on the axis they claim to differ on.
# --------------------------------------------------------------------------- #
def test_the_three_profiles_are_distinguishable_at_runtime():
    autonomous, supervised, benchmark = (
        build(AUTONOMOUS), build(SUPERVISED), build(BENCHMARK)
    )
    assert autonomous.profile == "autonomous"
    assert supervised.profile == "supervised"
    assert benchmark.profile == "benchmark"

    # The axis: what happens to an off-plan consequential action.
    assert autonomous.broker.defer_to_binding is False
    assert supervised.broker.defer_to_binding is True

    # Attention is a budget on the supervised profile and absent on the others.
    assert autonomous.broker.audit_budget == 0
    assert supervised.broker.audit_budget == 8
    assert benchmark.broker.audit_budget is None


def test_only_the_benchmark_profile_runs_the_corpus_derived_rules():
    """The reason the benchmark profile is separate at all."""
    assert build(BENCHMARK).broker.session_rules is True
    assert build(AUTONOMOUS).broker.session_rules is False
    assert build(SUPERVISED).broker.session_rules is False


def test_no_shipped_profile_enables_a_hazard():
    for profile in PROFILES.values():
        for hazard in HAZARDS:
            assert not profile.switches.get(hazard), (
                f"{profile.name} enables {hazard}"
            )
        assert profile.accepted_hazards == {}


# --------------------------------------------------------------------------- #
# It cannot decay back into anonymous booleans.
# --------------------------------------------------------------------------- #
def test_every_switch_a_profile_sets_carries_a_reason():
    """A profile is reviewable only if each setting says why it is that way."""
    for profile in PROFILES.values():
        unexplained = sorted(set(profile.switches) - set(profile.rationale))
        assert not unexplained, f"{profile.name}: no reason given for {unexplained}"


def test_changing_a_switch_requires_a_fresh_reason():
    """Inheriting the parent's reason for a value you just changed is worse than
    having none: the profile then explains a setting it no longer has."""
    with pytest.raises(ValueError, match="no rationale given"):
        SUPERVISED.with_switches(audit_budget=99)

    variant = SUPERVISED.with_switches(
        audit_budget=99, rationale={"audit_budget": "ops sized it for this tenant"}
    )
    assert variant.switches["audit_budget"] == 99
    assert "ops sized it" in variant.rationale["audit_budget"]
    assert variant.name.endswith("+custom")


def test_restating_a_switch_at_its_existing_value_needs_no_new_reason():
    unchanged = SUPERVISED.with_switches(audit_budget=8)
    assert unchanged.switches["audit_budget"] == 8


def test_a_posture_switch_cannot_be_overridden_at_the_call_site():
    """That is how a deployment ends up running a posture nobody chose."""
    with pytest.raises(ValueError, match="already sets"):
        SUPERVISED.build(GOAL, scope=SCOPE, graduated=False)


def test_authority_still_comes_from_the_caller():
    """A profile decides posture; the grant decides authority."""
    stack = SUPERVISED.build(GOAL, scope=SCOPE, entailment_judge=None)
    assert stack.broker.scope is SCOPE


def test_a_hazard_cannot_be_enabled_without_acknowledging_it():
    reckless = dataclasses.replace(
        SUPERVISED,
        name="reckless",
        switches={**SUPERVISED.switches, "defer_allows_bound": True},
    )
    with pytest.raises(ValueError, match="defer_allows_bound"):
        reckless.build(GOAL, scope=SCOPE)


def test_the_hazard_message_carries_the_measurement():
    """A warning without a number is an opinion.

    `defer_allows_bound` took AgentDojo travel ASR from 5.6% to 27.8%; the flag
    exists so that result reproduces, not so it can be switched on.
    """
    assert "27.8%" in HAZARDS["defer_allows_bound"]
    assert "denial_diagnosis.md" in HAZARDS["defer_allows_bound"]


def test_describe_prints_the_posture_with_its_reasons():
    text = SUPERVISED.describe()
    assert "profile: supervised" in text
    for key in SUPERVISED.switches:
        assert key in text


def test_get_profile_names_what_it_knows():
    assert get_profile("supervised") is SUPERVISED
    with pytest.raises(KeyError, match="autonomous, benchmark, supervised"):
        get_profile("nonexistent")


# --------------------------------------------------------------------------- #
# The profiles do what their intent says when an action arrives.
# --------------------------------------------------------------------------- #
def test_autonomous_refuses_where_supervised_asks():
    """One action, two postures, two different outcomes, the whole point."""
    from agentauth.capabilities.monitor.action import Action

    action = Action(0, "tool", "out-of-scope", "write", args={"n": 1})

    autonomous = build(AUTONOMOUS).authorize(action)
    supervised = build(SUPERVISED).authorize(action)

    # Autonomous has no attention to spend, so the question becomes a refusal.
    assert autonomous.outcome == "deny"
    assert any("audit budget exhausted" in r for r in autonomous.reasons)

    # Supervised asks.
    assert supervised.outcome == "step_up"
