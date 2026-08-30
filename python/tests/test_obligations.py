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


def test_a_refused_prerequisite_does_not_satisfy_an_obligation() -> None:
    """The fail-open this rung shipped with, and the reason it is tested here.

    The prerequisite was first recorded next to the trajectory append, which
    runs BEFORE the intent envelope, the flow tracker and the detector. An
    action any of those went on to DENY still satisfied a later obligation, so
    calling the prerequisite in a form that gets refused let the gated action
    walk through. It is recorded on the allow path now, where nothing
    downstream can still refuse.
    """
    from clayseal.capabilities.broker import Outcome, SessionBroker
    from clayseal.capabilities.monitor import Action
    from clayseal.capabilities.scoping.goal import GoalSpec
    from clayseal.core.task_scope import TaskScope

    class _Dev:
        in_plan = False
        reasons = ("off-plan",)
        reason = "off-plan"
        shape = None

    class _DenyEnvelope:
        """A late gate that refuses everything reaching it."""

        def check_slots(self, *a, **k): return None
        def conforms(self, *a, **k): return _Dev()
        def feasible(self, *a, **k): return True
        def last_deviation(self, *a, **k): return _Dev()
        def surface_is_comparable(self, *a, **k): return True

    rule = Obligation(gated=frozenset({"commit"}),
                      requires=frozenset({"prep"}), source="t")

    def _broker(ledger, envelope=None):
        return SessionBroker(
            goal=GoalSpec(query_id="q", summary="prep before commit"),
            scope=TaskScope(allowed_resources=["mcp:tool:prep", "mcp:tool:commit"],
                            allowed_actions=[]),
            obligations=ledger, intent_envelope=envelope)

    def _act(tool, step):
        return Action(step=step, tool=tool, resource=f"mcp:tool:{tool}",
                      verb="write", args={}, meta={})

    refused = ObligationLedger(obligations=[rule])
    assert _broker(refused, _DenyEnvelope()).authorize(
        _act("prep", 0)).outcome is Outcome.DENY
    assert not refused.check("commit")[0], (
        "a DENIED prerequisite satisfied the obligation")

    # Control: a prerequisite that is actually permitted must still satisfy it,
    # or the fix would be indistinguishable from disabling the rung.
    allowed = ObligationLedger(obligations=[rule])
    broker = _broker(allowed)
    assert broker.authorize(_act("prep", 0)).outcome is Outcome.ALLOW
    assert allowed.check("commit")[0]
    assert broker.authorize(_act("commit", 1)).outcome is Outcome.ALLOW
