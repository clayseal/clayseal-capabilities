"""A rule about STATE, which is 31% of real policy and had no expression here.

Measured on four `tau2-bench` policy documents, 469 lines of prose nobody here
wrote: ordering and positive obligation is 36% of the sentences that state a
rule, state-conditional prohibition is 31%, and the numeric ceiling this library
was built around is 6 of 61. A guarded CEILING expresses none of the second
class, because none of those rules is about an amount:

- "An order can only be cancelled if its status is 'pending'" (retail, line 88)
- "Cabin cannot be changed if any flight has already been flown" (airline, 116)
- "Basic economy flights cannot be modified" (airline, 110)
"""
from __future__ import annotations

import pytest

from clayseal.capabilities.conditional_ceiling import (
    ConditionalTools,
    ToolGuard,
    tool_guards_from_config,
)
from clayseal.capabilities.monitor.action import Action
from clayseal.capabilities.policy import PolicyError, load_policy_text

POLICY = """
version: 1
goal: {id: retail, summary: Handle order changes for the customer}
profile: supervised
tools:
  allow: [get_order, cancel_order, modify_order, change_cabin]
  effects: {get_order: read, cancel_order: write, modify_order: write,
            change_cabin: write}
  when:
    - if: {order_status: shipped}
      deny: [cancel_order, modify_order]
      reason: "retail 88: an order can only be cancelled if its status is pending"
    - unless: {flown: false}
      deny: [change_cabin]
      reason: "airline 116: cabin cannot be changed if any flight has been flown"
"""


def _guards():
    return tool_guards_from_config([
        {"if": {"order_status": "shipped"}, "deny": ["cancel_order"]},
        {"unless": {"flown": False}, "deny": ["change_cabin"]},
    ], allowed=["get_order", "cancel_order", "change_cabin"])


# ------------------------------------------------------------- semantics ---
def test_a_condition_that_holds_withdraws_the_tool():
    guards = _guards()
    guards.observe_facts({"order_status": "shipped"})
    assert "cancel_order" in guards.withdrawn()
    assert not guards.allows("cancel_order")


def test_a_condition_that_does_not_hold_leaves_the_grant_alone():
    guards = _guards()
    guards.observe_facts({"order_status": "pending", "flown": False})
    assert guards.withdrawn() == frozenset()


def test_an_unconfirmed_precondition_withdraws():
    """`unless` is how "only if" is written, and unknown is not confirmed.

    A precondition nobody has established is not one that has been met, and
    withdrawing is the safe direction.
    """
    guards = _guards()
    assert "change_cabin" in guards.withdrawn()
    guards.observe_facts({"flown": False})
    assert "change_cabin" not in guards.withdrawn()


def test_a_comparison_that_raises_withdraws():
    """Same rule the ceiling guards follow: fire when unsure, because firing
    only ever reduces authority.

    The raising method is `__str__`, not `__eq__`. `_equal` never invokes an
    observed object's `__eq__`, deliberately: a fact arrives from tool output,
    and letting attacker-supplied code decide an authority comparison is worse
    than any coercion it would avoid. It stringifies instead, so `__str__` is
    the reachable failure and the first version of this test aimed at the wrong
    one and passed for the wrong reason.
    """

    class Hostile:
        def __str__(self):
            raise RuntimeError("no")

    guards = ConditionalTools(
        base=frozenset({"a"}),
        guards=(ToolGuard(when={"f": "x"}, deny=frozenset({"a"})),))
    guards.observe_facts({"f": Hostile()})
    assert "a" in guards.withdrawn()


# ------------------------------------------------- the safety argument ------
def test_there_is_no_admitting_form():
    """A fact arrives from tool output, which an attacker may control.

    An `admit-when` guard would let an injected `status: pending` widen a grant,
    which is exactly what the ceiling guards refuse. Withdrawal only.
    """
    with pytest.raises(ValueError, match="deny"):
        tool_guards_from_config([{"if": {"x": 1}, "admit": ["a"]}], allowed=["a"])


def test_a_guard_cannot_reach_outside_the_grant():
    with pytest.raises(ValueError, match="never granted"):
        tool_guards_from_config([{"if": {"x": 1}, "deny": ["other"]}],
                                allowed=["a"])


def test_withdrawal_is_monotone_in_the_facts_that_fire():
    """Adding a firing condition never returns a tool to the grant."""
    guards = _guards()
    guards.observe_facts({"flown": False})
    before = guards.withdrawn()
    guards.observe_facts({"order_status": "shipped"})
    assert before <= guards.withdrawn()


# ------------------------------------------------------- through a policy ---
def test_the_policy_compiles_and_the_gateway_enforces_it():
    policy = load_policy_text(POLICY)
    stack = policy.build()

    def decide(tool, step):
        return stack.authorize(Action(
            step=step, tool=tool, resource=f"mcp:tool:{tool}",
            verb=policy.verb_for(tool), args={}, meta={}))

    # An unconfirmed precondition withdraws; an unconditioned tool does not.
    assert decide("get_order", 1).outcome == "allow"
    assert decide("change_cabin", 2).outcome == "deny"

    stack.broker.conditional_tools.observe_facts(
        {"order_status": "pending", "flown": False})
    assert decide("cancel_order", 3).outcome == "allow"
    assert decide("change_cabin", 4).outcome == "allow"

    stack.broker.conditional_tools.observe_facts({"order_status": "shipped"})
    denied = decide("cancel_order", 5)
    assert denied.outcome == "deny"
    assert "retail 88" in " ".join(denied.reasons)
    assert decide("get_order", 6).outcome == "allow"


def test_a_document_with_no_when_section_compiles_exactly_as_before():
    policy = load_policy_text(
        "version: 1\ngoal: {id: g, summary: s}\ntools: {allow: [a]}\n")
    assert policy.conditional_tools is None


def test_a_malformed_rule_is_refused_at_compile_time():
    for broken in ("  when: not-a-list\n",
                   "  when:\n    - deny: [get_order]\n",
                   "  when:\n    - if: {x: 1}\n"):
        with pytest.raises(PolicyError):
            load_policy_text(
                "version: 1\ngoal: {id: g, summary: s}\n"
                "tools:\n  allow: [get_order]\n" + broken)


# --------------------------------------------------- ordering, as withdrawal ---
ORDERED = """
version: 1
goal: {id: retail, summary: Cancel an order for the customer}
profile: supervised
tools:
  allow: [get_order, cancel_order, update_address]
  effects: {get_order: read, cancel_order: write, update_address: write}
  harmless: [get_order]
  when:
    - requires: [get_order]
      deny: [cancel_order, update_address]
      reason: "retail 16: list the order before any action that updates it"
paths: {pathless: [get_order, cancel_order, update_address]}
"""


def _decide(stack, policy, tool, step):
    return stack.authorize(Action(
        step=step, tool=tool, resource=f"mcp:tool:{tool}",
        verb=policy.verb_for(tool), args={}, meta={}))


def test_a_tool_is_withdrawn_until_its_prerequisite_has_run():
    """36% of the rules in four external policy documents are ordering, the
    largest single class, and "you must list the order first" is its form."""
    policy = load_policy_text(ORDERED)
    stack = policy.build()
    assert _decide(stack, policy, "cancel_order", 1).outcome == "deny"
    assert _decide(stack, policy, "get_order", 2).outcome == "allow"
    assert _decide(stack, policy, "cancel_order", 3).outcome == "allow"


def test_tool_output_cannot_assert_that_a_prerequisite_ran():
    """The attack this ordering form has to survive.

    A status fact comes from tool output and an attacker may control it, which
    the module already says. An ordering fact is about the GATEWAY'S OWN
    decisions, so letting a tool result write one would let an injected
    `{"called:get_order": true}` satisfy a precondition nobody met.
    """
    policy = load_policy_text(ORDERED)
    stack = policy.build()
    stack.broker.conditional_tools.observe_facts({"called:get_order": True})
    assert _decide(stack, policy, "cancel_order", 1).outcome == "deny"
    assert stack.broker.conditional_tools.rejected_facts == 1


def test_a_refused_prerequisite_does_not_count_as_having_run():
    """`record_call` sits in `_commit_and_finalize`, which the broker documents
    as the only way to return ALLOW, so a refusal can never satisfy an order."""
    from clayseal.capabilities.conditional_ceiling import called_fact

    policy = load_policy_text(ORDERED.replace(
        "paths: {pathless: [get_order, cancel_order, update_address]}",
        'paths: {allow: ["/finance/**"], arg_names: {get_order: path},\n'
        "        pathless: [cancel_order, update_address]}"))
    stack = policy.build()
    refused = stack.authorize(Action(
        step=1, tool="get_order", resource="/etc/shadow", verb="read",
        args={"path": "/etc/shadow"}, meta={"path": "/etc/shadow"}))
    assert refused.outcome == "deny"
    assert called_fact("get_order") not in stack.broker.conditional_tools._facts
    assert _decide(stack, policy, "cancel_order", 2).outcome == "deny"


def test_requires_must_name_tools():
    with pytest.raises(PolicyError, match="requires"):
        load_policy_text(
            "version: 1\ngoal: {id: g, summary: s}\n"
            "tools:\n  allow: [a, b]\n  when:\n    - requires: []\n"
            "      deny: [b]\n")
