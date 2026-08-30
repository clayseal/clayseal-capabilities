"""Precedence rules read from the sealed goal.

A budget bounds a running total; these bound a running order. The controls
matter more than the gains: a derived rule that is wrong refuses work nobody
prohibited, so most of this file is about when the deriver declines.
"""

from __future__ import annotations

from clayseal.capabilities import Obligation, ObligationLedger, derive_obligations

CATALOG = {"load_policy", "checklist_item", "checklist_status",
           "commit_irreversible", "nonessential_chat"}


def test_it_reads_a_before_rule() -> None:
    rules = derive_obligations("Full checklist before irreversible commit", CATALOG)
    assert len(rules) == 1
    assert "commit_irreversible" in rules[0].gated
    assert "checklist_item" in rules[0].requires


def test_it_reads_a_without_rule() -> None:
    rules = derive_obligations("No ship without cook-temp CCP",
                               {"ship", "cook_temp", "log_ccp"})
    assert len(rules) == 1
    assert rules[0].gated == frozenset({"ship"})


def test_a_destination_rule_yields_no_obligation() -> None:
    """Control: the deriver must decline on rules that are not orderings.

    Without this it would be enough to return something for every goal, and
    every later assertion would be about a mechanism that fires indiscriminately.
    """
    assert derive_obligations("Pay Acme and Beta only", {"pay", "list_invoices"}) == []
    assert derive_obligations("", CATALOG) == []
    assert derive_obligations("Summarise the inbox", CATALOG) == []


def test_an_unresolvable_side_yields_nothing() -> None:
    """A prerequisite the session cannot perform would gate the action forever."""
    assert derive_obligations("Manager sign-off before commit_irreversible",
                              {"commit_irreversible"}) == []
    assert derive_obligations("Full checklist before launching the rocket",
                              {"checklist_item"}) == []


def test_a_tool_is_never_its_own_prerequisite() -> None:
    rules = derive_obligations("checklist_item before checklist_item", CATALOG)
    assert all(not (r.gated & r.requires) for r in rules)


def test_the_ledger_gates_until_the_prerequisite_runs() -> None:
    rule = Obligation(gated=frozenset({"commit_irreversible"}),
                      requires=frozenset({"checklist_item"}), source="test")
    ledger = ObligationLedger(obligations=[rule])
    allowed, why = ledger.check("commit_irreversible")
    assert not allowed
    assert "checklist_item" in why

    ledger.observe("checklist_item")
    allowed, _ = ledger.check("commit_irreversible")
    assert allowed


def test_an_ungated_tool_is_never_refused() -> None:
    """Control: the ledger must not refuse everything before its prerequisite."""
    rule = Obligation(gated=frozenset({"commit_irreversible"}),
                      requires=frozenset({"checklist_item"}), source="test")
    ledger = ObligationLedger(obligations=[rule])
    for tool in ("load_policy", "checklist_item", "nonessential_chat"):
        allowed, _ = ledger.check(tool)
        assert allowed, tool


def test_no_obligations_means_no_gating() -> None:
    """The property that lets this ship: unconfigured is unchanged."""
    ledger = ObligationLedger()
    for tool in CATALOG:
        assert ledger.check(tool)[0]


def test_a_tool_matching_both_sides_goes_to_the_stronger_one() -> None:
    """The bug that cost a scenario: a tie deleted the tool from both sides.

    `disclose_related` shares one token with each half of "Disclose before
    related-party pay". Counting shared tokens ties, and the first version
    dropped such a tool from both sides, producing no rule at all. Coverage of
    the phrase resolves it: 1 of 1 tokens of "Disclose" against 1 of 3 of
    "related-party pay".
    """
    rules = derive_obligations(
        "Disclose before related-party pay",
        {"conflict_register", "disclose_related", "load_policy", "pay_log", "pay_vendor"})
    assert len(rules) == 1
    assert rules[0].requires == frozenset({"disclose_related"})
    assert "pay_vendor" in rules[0].gated


def test_it_reads_a_then_rule() -> None:
    rules = derive_obligations("Arm then pay; checks destroy bit",
                               {"arm", "benign", "check", "load_policy", "pay", "tr"})
    assert len(rules) == 1
    assert rules[0].gated == frozenset({"pay"})
    assert rules[0].requires == frozenset({"arm"})


def test_an_equal_match_on_both_sides_is_still_dropped() -> None:
    """Control: coverage breaks ties that mean something, not every tie.

    A tool that covers both phrases equally is evidence of neither side, and
    guessing which would invent an obligation.
    """
    rules = derive_obligations("audit before audit_review", {"audit_review"})
    assert all(not (r.gated & r.requires) for r in rules)
