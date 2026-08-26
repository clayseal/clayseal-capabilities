"""A written business rule becomes a policy draft a person then reviews.

The rung that matters is inert when nobody declares a ceiling, and 0 of 520
external corpus tasks do. Organisations DO write their ceilings down, in
delegation-of-authority matrices and AP policies, just not in a form a gateway
can read. This is that bridge.

The tests are mostly about what it refuses to do quietly. A draft that looks
complete is worse than one that admits what it dropped, because a rule that
vanished in translation is one the reviewer has no way to notice.
"""
from __future__ import annotations

import pytest

from agentauth.capabilities.policy_draft import extract, to_yaml

DOCUMENT = """
# Accounts Payable - Delegation of Authority

3.1 A single vendor payment must not exceed $10,000.
3.2 Total disbursements must not exceed $50,000 in any rolling 24 hours.
3.3 Any payment over $10,000 requires approval from a Finance Manager.
3.4 Each invoice may be paid once only.
4.1 Refunds are limited to $5,000 per day in aggregate.
4.2 No more than 20 refunds may be issued per day.
5.1 Confirmations may only be sent to addresses at acme-internal.com.
6.2 Production ledger files (*.ledger) must never be modified.
7.1 The person who prepares a payment may not approve it.
""".strip()


@pytest.fixture(scope="module")
def draft():
    return extract(DOCUMENT)


def _of(draft, kind):
    return [r for r in draft.rules if r.kind == kind]


# --------------------------------------------------------------------------- #
# What it reads
# --------------------------------------------------------------------------- #
def test_a_money_ceiling_is_extracted_with_its_line(draft):
    values = _of(draft, "value")
    assert {r.payload["ceiling"] for r in values} == {"10000", "50000", "5000"}
    assert all(r.line_no > 0 for r in values)
    assert all(r.source in DOCUMENT for r in values)


def test_a_period_becomes_a_window():
    """"$50,000 in any rolling 24 hours" is a window, not a session total."""
    rule = next(r for r in extract("Total must not exceed $50,000 in any rolling "
                                   "24 hours.").rules if r.kind == "value")
    assert rule.payload["window_seconds"] == 86400


def test_the_longest_period_name_wins():
    """"24 hours" contains "hour". Matching the short one read a daily cap as an
    hourly one, a rule twenty-four times tighter than the document says."""
    daily = next(r for r in extract(
        "Total must not exceed $1,000 in any rolling 24 hours.").rules
        if r.kind == "value")
    assert daily.payload["window_seconds"] == 86400
    hourly = next(r for r in extract(
        "Total must not exceed $1,000 per hour.").rules
        if r.kind == "value")
    assert hourly.payload["window_seconds"] == 3600


def test_a_count_ceiling_is_separated_from_a_money_one(draft):
    calls = _of(draft, "calls")
    assert [r.payload["ceiling"] for r in calls] == [20]
    assert calls[0].payload["window_seconds"] == 86400


def test_once_only_becomes_an_identity_rule(draft):
    assert _of(draft, "identity")


def test_a_domain_becomes_an_egress_allow(draft):
    egress = [r for r in _of(draft, "egress") if not r.payload["deny"]]
    assert egress and egress[0].payload["domains"] == ["acme-internal.com"]


def test_a_glob_path_is_found_even_though_it_starts_with_a_star(draft):
    """`\\b` cannot anchor before `*`, so a rule about `*.ledger` matched nothing
    at all until the anchor was dropped."""
    paths = _of(draft, "paths")
    assert paths and "*.ledger" in paths[0].payload["paths"]
    assert paths[0].payload["deny"] is True


# --------------------------------------------------------------------------- #
# What it refuses to drop
# --------------------------------------------------------------------------- #
def test_a_rule_it_cannot_translate_is_reported_not_dropped(draft):
    """Segregation of duties is a real rule and this layer cannot express it.

    Saying so is the whole point. A draft that silently omits it looks complete.
    """
    assert any("prepares a payment may not approve" in r.source
               for r in draft.unmapped)


def test_every_untranslated_sentence_reaches_the_rendered_output(draft):
    rendered = to_yaml(draft)
    assert "NOT TRANSLATED" in rendered
    for rule in draft.unmapped:
        assert f"line {rule.line_no}" in rendered


def test_a_sentence_that_is_not_a_rule_is_ignored_entirely():
    d = extract("The AP team meets on Tuesdays. Coffee is in the kitchen.")
    assert not d.rules and not d.unmapped


# --------------------------------------------------------------------------- #
# What the draft says about itself
# --------------------------------------------------------------------------- #
def test_the_output_says_it_is_not_a_grant(draft):
    rendered = to_yaml(draft)
    assert "NOT a grant until a person has reviewed it" in rendered
    assert "clayseal policy lint" in rendered


def test_every_rule_cites_the_line_it_came_from(draft):
    rendered = to_yaml(draft)
    for rule in draft.rules:
        if rule.kind in ("value", "calls", "egress", "paths"):
            assert f"line {rule.line_no}" in rendered, rule.cite()


def test_a_per_call_limit_is_flagged_rather_than_silently_made_cumulative(draft):
    """"A single payment must not exceed $10,000" is not a session total.

    Rendering it as one is TIGHTER than the document, which is the safe
    direction and still not what was written, so the draft says so.
    """
    rendered = to_yaml(draft)
    assert "reads as a per-CALL limit" in rendered


def test_requires_approval_is_flagged_as_a_step_up_not_a_ceiling(draft):
    """A ceiling refuses; the document asked for someone to be asked."""
    rendered = to_yaml(draft)
    assert "step-up and not a ceiling" in rendered


def test_the_placeholders_are_loud(draft):
    rendered = to_yaml(draft)
    assert "REPLACE-ME" in rendered
    assert "TODO" in rendered


# --------------------------------------------------------------------------- #
# The round trip
# --------------------------------------------------------------------------- #
def test_a_reviewed_draft_compiles_and_enforces(tmp_path):
    """Document, draft, review, working grant. The whole point of the module."""
    from agentauth.capabilities.monitor.action import Action
    from agentauth.capabilities.policy import load_policy

    rendered = to_yaml(extract(DOCUMENT), goal_id="ap",
                       goal_summary="Process the approved AP invoice queue",
                       tools=["pay_vendor", "issue_refund", "send_email"])
    # The four decisions the draft asks a person to make.
    rendered = rendered.replace(
        "# TODO: declare each tool's effect and mark the harmless ones.\n"
        "  # effects:  {pay_vendor: transfer, send_email: send}\n"
        "  # harmless: []",
        "effects: {pay_vendor: transfer, issue_refund: transfer, send_email: send}\n"
        "  harmless: [send_email]")
    rendered = rendered.replace(
        "# TODO: name the argument each tool carries its path in, or the\n"
        "  #       scope cannot be applied to it. See docs/POLICY.md.\n"
        "  # arg_names: {}",
        "pathless: [pay_vendor, issue_refund, send_email]")
    rendered = rendered.replace(
        "# TODO: map each tool to the budget it debits and the\n"
        "      #       argument carrying the amount.\n"
        "      # pay_vendor: {arg: amount, budget: budget_1}",
        "pay_vendor: {arg: amount, budget: budget_2, identity: [invoice]}\n"
        "      issue_refund: {arg: amount, budget: budget_2}")
    rendered = rendered.replace(
        "# TODO: map each tool to the count budget it debits.\n"
        "      # issue_refund: count_1",
        "issue_refund: count_1")

    path = tmp_path / "reviewed.yaml"
    path.write_text(rendered)
    policy = load_policy(path)
    assert [f for f in policy.lint() if f.level == "error"] == []

    gateway = policy.build()
    first = gateway.authorize(Action(step=0, tool="pay_vendor", verb="transfer",
                                     resource="mcp:tool:pay_vendor",
                                     args={"amount": 30000, "invoice": "INV-1"}))
    assert first.allowed
    over = gateway.authorize(Action(step=1, tool="pay_vendor", verb="transfer",
                                    resource="mcp:tool:pay_vendor",
                                    args={"amount": 25000, "invoice": "INV-2"}))
    assert not over.allowed, "the $50,000 rolling ceiling did not hold"
    dupe = gateway.authorize(Action(step=2, tool="pay_vendor", verb="transfer",
                                    resource="mcp:tool:pay_vendor",
                                    args={"amount": 100, "invoice": "INV-1"}))
    assert not dupe.allowed, "'each invoice paid once only' did not hold"


# ------------------------------- the two large classes, extracted and bound ---
# One sentence per line, because the extractor reads a line at a time. A
# sentence wrapped across two lines has its tools on one and its rule on the
# other, and neither half binds. The tau2-bench documents happen to keep their
# rules on one line each, which is why they extract; a document that wraps
# would not, and that is a real limit rather than a property of these tests.
RETAIL = """
Before taking any action that updates the database (cancel, return), you must list the order first.
An order can only be cancelled if its status is 'pending'.
An order can only be returned if its status is 'delivered'.
Cabin cannot be changed if any flight in the reservation has already been flown.
"""
CATALOG = ["get_order", "list_orders", "cancel_order", "return_order",
           "change_cabin"]


def _rules(kind):
    return [r for r in extract(RETAIL, tools=CATALOG).rules if r.kind == kind]


def test_an_ordering_rule_binds_to_the_tools_it_names():
    """36% of the rules in four external policy documents are ordering, the
    largest single class, and none was extractable before the catalog was
    available to bind them to."""
    ordering = _rules("ordering")
    assert len(ordering) == 1
    assert ordering[0].payload["requires"] == ["list_orders"]
    assert set(ordering[0].payload["deny"]) >= {"cancel_order", "return_order"}


def test_an_only_if_rule_becomes_an_unless_withdrawal():
    """`only cancelled if pending` withdraws UNLESS pending. Reading it as
    `if pending` would invert the rule, and `only` sits inside the match, which
    is why a prefix-only check dropped every rule of this shape."""
    conditional = {tuple(r.payload["deny"]): r for r in _rules("conditional")}
    cancel = conditional[("cancel_order",)]
    assert cancel.payload["unless"] == {"status": "pending"}


def test_a_cannot_if_rule_becomes_an_if_withdrawal():
    """The opposite direction: the condition names the forbidden state."""
    conditional = {tuple(r.payload["deny"]): r for r in _rules("conditional")}
    cabin = conditional[("change_cabin",)]
    assert "if" in cabin.payload


def test_nothing_is_extracted_without_a_catalog():
    """A rule of these shapes is ABOUT a tool. With no catalog there is nothing
    to bind to, and inventing a tool name would be worse than a TODO."""
    assert not [r for r in extract(RETAIL).rules
                if r.kind in ("ordering", "conditional")]


def test_the_draft_round_trips_into_enforcement(tmp_path):
    """The whole point: a document nobody here wrote becomes decisions."""
    from agentauth.capabilities.monitor.action import Action
    from agentauth.capabilities.policy import load_policy_text

    tools = ["get_order", "list_orders", "cancel_order"]
    document = to_yaml(extract(RETAIL, tools=tools), goal_id="r",
                       goal_summary="Handle order changes", tools=tools)
    document = document.replace(
        "  # TODO: declare each tool's effect and mark the harmless ones.\n"
        "  # effects:  {pay_vendor: transfer, send_email: send}\n"
        "  # harmless: []",
        "  effects: {get_order: read, list_orders: read, cancel_order: write}\n"
        "  harmless: [get_order, list_orders]")
    document += "\npaths: {pathless: [get_order, list_orders, cancel_order]}\n"

    policy = load_policy_text(document)
    stack = policy.build()

    def decide(tool, step, facts=None):
        if facts:
            stack.broker.conditional_tools.observe_facts(facts)
        return stack.authorize(Action(
            step=step, tool=tool, resource=f"mcp:tool:{tool}",
            verb=policy.verb_for(tool), args={}, meta={}))

    # Both rules withdraw it at step one: nothing has been listed and no status
    # is known. Either citation is correct, so this asserts the refusal and the
    # fact that it names a line of the document rather than a dictionary.
    ordered = decide("cancel_order", 1)
    assert ordered.outcome == "deny"
    assert "line " in " ".join(ordered.reasons)

    assert decide("list_orders", 2).outcome == "allow"
    assert decide("cancel_order", 3, {"status": "shipped"}).outcome == "deny"
    assert decide("cancel_order", 4, {"status": "pending"}).outcome == "allow"


def test_a_refusal_cites_the_line_it_came_from():
    tools = ["list_orders", "cancel_order"]
    document = to_yaml(extract(RETAIL, tools=tools), tools=tools)
    assert "reason: \"line " in document
