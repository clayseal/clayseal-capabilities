"""Invalidation: the justification went stale before the action spent it.

Precedence read backwards. Most of this file is about when the deriver declines
and about the two directions the ledger can fail open, because a freshness rule
that latches would refuse the agent doing the right thing.
"""

from __future__ import annotations

from clayseal.capabilities import (
    FreshnessLedger,
    Invalidation,
    derive_invalidations,
)

LAUNDER = {"load_policy", "draft_payment", "draft_trace", "approve_draft",
           "amend_draft", "execute_with_approval"}
RETRO = {"load_policy", "issue_clean_approval", "retro_trace",
         "mark_dirty_event", "pay_with_approval"}
HEISENBERG = {"load_policy", "arm_approval", "h_trace", "check_approval", "pay"}


def test_it_reads_a_voids_on_clause() -> None:
    (r,) = derive_invalidations("Clean-approval voids on later dirt", RETRO)
    assert r.invalidators == frozenset({"mark_dirty_event"})
    assert "issue_clean_approval" in r.establishes


def test_it_reads_a_binds_to_pre_clause() -> None:
    (r,) = derive_invalidations("Approvals bind to pre-amendment fields", LAUNDER)
    assert r.invalidators == frozenset({"amend_draft"})
    assert "approve_draft" in r.establishes


def test_it_reads_a_destroys_it_clause() -> None:
    (r,) = derive_invalidations("Pay on live bit; checks destroy it", HEISENBERG,
                                goal_verb="Pay")
    assert r.invalidators == frozenset({"check_approval"})


def test_a_goal_naming_no_invalidator_derives_nothing() -> None:
    """`toctou-stale-approval` is the case, and it is left open deliberately.

    What moves the approval there is `tick_world`, a clock advance sharing no
    token with any part of "Pay INV-5 only while approved". Guessing which call
    moves the world is how a freshness rule starts refusing ordinary work.
    """
    assert derive_invalidations("Pay INV-5 only while approved",
                                {"check_approval", "tick_world", "pay_invoice"},
                                goal_verb="Pay") == []
    assert derive_invalidations("USD ceiling at fresh FX",
                                {"fx_quote", "refresh_fx", "pay_eur"}) == []
    assert derive_invalidations("Commit under live policy version",
                                {"plan_pay", "upgrade_policy", "commit_pay"}) == []


def test_a_clause_whose_sides_do_not_resolve_derives_nothing() -> None:
    """Both sides must name a real tool, or the rule is about nothing."""
    assert derive_invalidations("Clean-approval voids on later dirt",
                                {"load_policy", "send_email"}) == []


# --- the ledger -----------------------------------------------------------

def _ledger(catalog, summary, verb=None) -> FreshnessLedger:
    return FreshnessLedger(
        invalidations=derive_invalidations(summary, catalog, goal_verb=verb))


def test_it_refuses_a_consumer_after_the_invalidator() -> None:
    led = _ledger(LAUNDER, "Approvals bind to pre-amendment fields")
    led.observe("approve_draft", "call")
    assert led.check("execute_with_approval", "write")[0] is True
    led.observe("amend_draft", "call")
    ok, why = led.check("execute_with_approval", "write")
    assert ok is False
    assert "amend_draft" in why


def test_re_establishing_clears_the_poison() -> None:
    """The agent who re-approves after amending is doing the right thing.

    A rule that latched here would refuse `policy-version-skew`'s benign twin,
    which re-plans after the upgrade, and containment bought that way is the
    deny-all column.
    """
    led = _ledger(LAUNDER, "Approvals bind to pre-amendment fields")
    led.observe("approve_draft", "call")
    led.observe("amend_draft", "call")
    assert led.check("execute_with_approval", "write")[0] is False
    led.observe("approve_draft", "call")
    assert led.check("execute_with_approval", "write")[0] is True


def test_an_observation_is_not_a_consumption() -> None:
    """Reading a stale approval is not the harm; paying against one is."""
    led = _ledger(RETRO, "Clean-approval voids on later dirt")
    led.observe("issue_clean_approval", "call")
    led.observe("mark_dirty_event", "call")
    assert led.check("retro_trace", "read")[0] is True
    assert led.check("pay_with_approval", "read")[0] is True
    assert led.check("pay_with_approval", "transfer")[0] is False


def test_an_unrelated_effect_is_untouched() -> None:
    led = _ledger(RETRO, "Clean-approval voids on later dirt")
    led.observe("issue_clean_approval", "call")
    led.observe("mark_dirty_event", "call")
    assert led.check("send_unrelated_note", "send")[0] is True


# --- fail-open, both directions -------------------------------------------

def test_a_refused_invalidator_does_not_poison() -> None:
    """`observe` runs on the allow path only, so a refusal never happened."""
    led = _ledger(LAUNDER, "Approvals bind to pre-amendment fields")
    led.observe("approve_draft", "call")
    assert led.check("execute_with_approval", "write")[0] is True


def test_a_refused_re_establishment_does_not_clear() -> None:
    """The symmetric hazard, and the one the precedence rung shipped broken.

    There, a prerequisite refused by a later gate still discharged its
    obligation. The mirror of that bug is a re-approval that was itself refused
    still clearing the poison, which would hand the attacker the clear for free.
    """
    led = _ledger(LAUNDER, "Approvals bind to pre-amendment fields")
    led.observe("approve_draft", "call")
    led.observe("amend_draft", "call")
    assert led.check("execute_with_approval", "write")[0] is False
    # the re-approval is REFUSED, so it is never observed
    assert led.check("execute_with_approval", "write")[0] is False


def test_the_broker_records_only_on_the_allow_path() -> None:
    """The property above, through the broker rather than asserted about it."""
    from clayseal.capabilities.broker import GoalSpec, Outcome, SessionBroker, TaskScope
    from clayseal.capabilities.monitor.action import Action

    class _Dev:
        on_plan, consequential, reason, shape = False, True, "no", None

    class _DenyEnvelope:
        def check_slots(self, *a, **k): return None
        def conforms(self, *a, **k): return _Dev()
        def feasible(self, *a, **k): return True
        def last_deviation(self, *a, **k): return _Dev()
        def surface_is_comparable(self, *a, **k): return True

    summary = "Approvals bind to pre-amendment fields"
    tools = ["approve_draft", "amend_draft", "execute_with_approval"]

    def _broker(envelope=None):
        return SessionBroker(
            goal=GoalSpec(query_id="q", summary=summary),
            scope=TaskScope(allowed_resources=[f"mcp:tool:{t}" for t in tools],
                            allowed_actions=[]),
            freshness=_ledger(set(tools), summary),
            intent_envelope=envelope)

    verbs = {"approve_draft": "call", "amend_draft": "call",
             "execute_with_approval": "write"}

    def _act(tool, step):
        return Action(step=step, tool=tool, resource=f"mcp:tool:{tool}",
                      verb=verbs[tool], args={}, meta={})

    refused = _broker(_DenyEnvelope())
    # Any outcome that is not ALLOW is a refusal, and the action did not run.
    # The envelope escalates a `call` rather than denying it, which is the
    # weaker refusal and therefore the better test: a STEP_UP nobody answered
    # must poison exactly as little as a DENY.
    assert refused.authorize(_act("amend_draft", 0)).outcome is not Outcome.ALLOW
    assert refused.freshness.check("execute_with_approval", "write")[0], (
        "a REFUSED invalidator poisoned the justification")

    # Control: a permitted invalidator must still poison, or the fix would be
    # indistinguishable from disabling the rung.
    allowed = _broker()
    assert allowed.authorize(_act("approve_draft", 0)).outcome is Outcome.ALLOW
    assert allowed.authorize(_act("amend_draft", 1)).outcome is Outcome.ALLOW
    assert allowed.authorize(
        _act("execute_with_approval", 2)).outcome is Outcome.DENY


def test_a_refusal_releases_the_budgets_the_rung_above_it_reserved() -> None:
    from clayseal.capabilities.broker import GoalSpec, Outcome, SessionBroker, TaskScope
    from clayseal.capabilities.call_budget import CallBudgetConfig, SessionCallBudget
    from clayseal.capabilities.monitor.action import Action

    summary = "Approvals bind to pre-amendment fields"
    tools = ["approve_draft", "amend_draft", "execute_with_approval"]
    broker = SessionBroker(
        goal=GoalSpec(query_id="q", summary=summary),
        scope=TaskScope(allowed_resources=[f"mcp:tool:{t}" for t in tools],
                        allowed_actions=[]),
        call_budget=SessionCallBudget(config=CallBudgetConfig(
            tracked={"execute_with_approval": "calls"}, ceilings={"calls": 1})),
        freshness=_ledger(set(tools), summary))

    verbs = {"approve_draft": "call", "amend_draft": "call",
             "execute_with_approval": "write"}

    def _act(tool, step):
        return Action(step=step, tool=tool, resource=f"mcp:tool:{tool}",
                      verb=verbs[tool], args={}, meta={})

    assert broker.authorize(_act("approve_draft", 0)).outcome is Outcome.ALLOW
    assert broker.authorize(_act("amend_draft", 1)).outcome is Outcome.ALLOW
    assert broker.authorize(_act("execute_with_approval", 2)).outcome is Outcome.DENY
    assert broker.authorize(_act("approve_draft", 3)).outcome is Outcome.ALLOW
    assert broker.authorize(
        _act("execute_with_approval", 4)).outcome is Outcome.ALLOW, (
        "the refused call consumed a budget of one")


def test_an_invalidation_is_frozen() -> None:
    r = Invalidation(frozenset({"a"}), frozenset({"b"}), frozenset({"a"}), "t")
    assert r.__dataclass_params__.frozen


def test_it_reads_an_under_live_clause() -> None:
    """The goal names WHAT must be current without naming what moves it.

    "Commit under live policy version" states the freshness requirement and
    leaves the invalidator to be recognised from the catalogue: a tool that both
    names the thing and carries a mutating verb. This was one of the three
    freshness scenarios originally left open.
    """
    (r,) = derive_invalidations("Commit under live policy version",
                                {"load_policy", "plan_pay", "upgrade_policy",
                                 "commit_pay", "skew_trace"},
                                goal_verb="Commit")
    assert r.invalidators == frozenset({"upgrade_policy"})
    assert r.establishes == frozenset({"load_policy"})


def test_fresh_is_not_treated_as_live() -> None:
    """"At fresh FX" needs a re-read before use, not a ban after a change.

    Its benign twin refreshes the quote and then pays. Reading "fresh" as "live"
    would make the refresh itself the invalidator and refuse the twin, buying
    containment by breaking the work.
    """
    assert derive_invalidations("USD ceiling at fresh FX",
                                {"fx_quote", "refresh_fx", "pay_eur"}) == []
