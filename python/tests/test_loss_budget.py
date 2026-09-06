"""Relative loss budget: the production input for inferred rules.

Mandate-stated constraints are not in this selection. A running budget at
decision time is an attack, so everything here is compile-time only.
"""
from __future__ import annotations

import pytest

from clayseal.capabilities.derivation import refuted_by_traffic, seal
from clayseal.capabilities.loss_budget import select_under_budget, union_loss
from clayseal.capabilities.scoping.goal import GoalSpec


PRECEDENCE = {
    "precedence": [{"before": "checklist_item", "after": "commit_irreversible"}],
    "invalidations": [],
    "entities": [],
    "distinct_subjects": False,
    "idempotency": False,
}


def test_zero_budget_drops_a_rule_that_fires_on_known_good_traffic():
    """relative_loss=0 is full refutation."""
    # Benign twin commits without the checklist — the rule would refuse it.
    traces = [("commit_irreversible", {})]
    kept = select_under_budget(PRECEDENCE, traces, 0.0, clause="checklist first")
    assert kept["precedence"] == []


def test_zero_budget_keeps_a_rule_known_good_traffic_already_satisfies():
    traces = [("checklist_item", {}), ("commit_irreversible", {})]
    kept = select_under_budget(PRECEDENCE, traces, 0.0, clause="checklist first")
    assert kept["precedence"] == PRECEDENCE["precedence"]


def test_a_nonzero_budget_keeps_a_rule_whose_union_loss_fits():
    # One of two actions is refused (the commit without a checklist).
    traces = [("commit_irreversible", {}), ("pay_vendor", {"vendor": "acme"})]
    assert union_loss(PRECEDENCE, traces) == 0.5
    kept = select_under_budget(PRECEDENCE, traces, 0.5, clause="checklist first")
    assert kept["precedence"] == PRECEDENCE["precedence"]
    dropped = select_under_budget(PRECEDENCE, traces, 0.49, clause="checklist first")
    assert dropped["precedence"] == []


def test_a_budget_without_traces_is_refused_rather_than_decorative():
    with pytest.raises(ValueError, match="known-good"):
        select_under_budget(PRECEDENCE, [], 0.02)


def test_an_out_of_range_budget_is_refused():
    with pytest.raises(ValueError, match=r"\[0, 1\]"):
        select_under_budget(PRECEDENCE, [("checklist_item", {})], 1.5)


def test_select_under_zero_matches_refuted_by_traffic():
    traces = [("commit_irreversible", {}), ("pay_vendor", {"vendor": "ContingencyCo"})]
    compiled = {
        **PRECEDENCE,
        "entities": [{"key": "vendor", "allowed": ["acme"]}],
    }
    clause = "checklist before commit; pay acme only"
    selected = select_under_budget(compiled, traces, 0.0, clause=clause)
    refuted = refuted_by_traffic(compiled, traces, clause)
    assert selected["precedence"] == refuted["precedence"]
    assert selected["entities"] == refuted["entities"]


def test_seal_with_compiled_rules_does_not_parse_english():
    """The production path never consults a clause pattern."""
    goal = GoalSpec(
        query_id="t",
        summary="A must precede B, which no regex in this package matches",
    )
    compiled = {
        "precedence": [{"before": "checklist_item", "after": "commit_irreversible"}],
        "invalidations": [],
        "entities": [],
        "distinct_subjects": False,
        "idempotency": False,
    }
    traces = [("checklist_item", {}), ("commit_irreversible", {})]
    out = seal(
        goal,
        {"checklist_item", "commit_irreversible"},
        compiled=compiled,
        known_good=traces,
        relative_loss=0.0,
        lexical=False,
    )
    assert out["obligations"] is not None
    ok, why = out["obligations"].check("commit_irreversible")
    assert not ok
    out["obligations"].observe("checklist_item")
    ok, why = out["obligations"].check("commit_irreversible")
    assert ok


def test_seal_applies_structured_intent_even_without_a_compiler():
    goal = GoalSpec(
        query_id="t",
        summary="Pay the approved invoices",
        structured_intent={"vendors": ["Acme", "Beta"]},
    )
    out = seal(goal, {"pay_vendor"}, lexical=False)
    assert out["entities"] is not None
    allowed, _why, declared = out["entities"].check(
        "pay_vendor", {"vendor": "ContingencyCo"},
    )
    assert declared is True
    assert allowed is False


def test_union_loss_does_not_let_a_refused_call_establish_state():
    """A refused prerequisite must not discharge the obligation it was refused for."""
    compiled = {
        "precedence": [
            {"before": "checklist_item", "after": "commit_irreversible"},
        ],
        "invalidations": [],
        "entities": [],
        "distinct_subjects": False,
        "idempotency": False,
    }
    # First commit is refused; observing it would let the second through.
    traces = [("commit_irreversible", {}), ("commit_irreversible", {})]
    assert union_loss(compiled, traces) == 1.0


def test_from_goal_with_compiled_rungs_never_reaches_a_clause_pattern():
    """Sabotage: if a regex fires, the production path is still parsing English."""
    from clayseal.capabilities.deployable_stack import DeployableStack
    from clayseal.capabilities import obligations as ob

    def boom(*_a, **_kw):
        raise AssertionError("lexical derive_obligations was reached")

    original, ob.derive_obligations = ob.derive_obligations, boom
    try:
        stack = DeployableStack.from_goal(
            GoalSpec(query_id="t", summary="Full checklist before irreversible commit"),
            allowed_tools={"checklist_item", "commit_irreversible"},
            compiled_rungs=PRECEDENCE,
            known_good=[("checklist_item", {}), ("commit_irreversible", {})],
            relative_loss=0.0,
            derive_rungs=True,
        )
        assert stack.broker.obligations is not None
    finally:
        ob.derive_obligations = original
