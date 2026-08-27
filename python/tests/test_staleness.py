"""Observation freshness: the properties the mechanism must have.

The benchmark measures rates; this file pins the semantics that make those rates
mean what they say. Every test here corresponds to a way the check could look
like it works while doing something else.
"""
from __future__ import annotations

import pytest

from agentauth.capabilities.staleness import (
    CONSEQUENTIAL_VERBS, ObservationLedger, StalenessPolicy, content_version)

POLICY = StalenessPolicy(volatile=("record:*",), revalidate=True)
FREE = StalenessPolicy(volatile=("record:*",), revalidate=False)

KEY = "record:INV-000041"
V1 = {"id": "INV-000041", "amount": "1200.00", "payee": "acme_supplies_9931",
      "status": "pending"}
V2 = {**V1, "amount": "9500.00", "payee": "shell_holdings_4417"}


def _ledger(policy=POLICY, *versions):
    led = ObservationLedger()
    for payload in versions or (V1,):
        led.observe("get_invoice", "mcp:tool:get_invoice", payload,
                    policy=policy, path=KEY, structured_fields=payload)
    return led


def _oracle(payload):
    return lambda key: content_version(payload, payload)


# --------------------------------------------------------------------------- #
# The policy is a mandate, not a calibration
# --------------------------------------------------------------------------- #
def test_no_policy_means_no_behaviour_change():
    """A mandate written before this module existed must behave as it did."""
    led = ObservationLedger()
    empty = StalenessPolicy.from_mandate({})
    assert not empty.active
    verdict = led.check(tool="pay", verb="transfer", resource="r",
                        args={"amount": "9500.00"}, policy=empty)
    assert verdict.allowed


def test_the_policy_is_a_pure_function_of_the_mandate():
    """Invariant 1, in the form this axis takes.

    The velocity cap was withdrawn once for being derived from the label. There
    is no threshold to derive here: which objects are volatile and whether to
    re-read are declared, not learned, so no amount of traffic, attack or clean
, can move them. Asserted rather than assumed, because "there is no
    parameter" is exactly the claim an added parameter would silently break.
    """
    mandate = {"freshness": {"volatile": ["record:*"], "revalidate": True}}
    first = StalenessPolicy.from_mandate(mandate)
    for _ in range(50):
        led = _ledger(first, V1, V2)
        led.check(tool="pay", verb="transfer", resource="r", args=dict(V1),
                  policy=first, path=KEY, revalidate=_oracle(V2))
    assert StalenessPolicy.from_mandate(mandate) == first
    assert not hasattr(ObservationLedger, "calibrate")
    assert not hasattr(ObservationLedger, "observe_corpus")


def test_an_injected_instruction_cannot_widen_the_policy():
    """Policy comes from the mandate. Tool output reaches `observe`, never here."""
    poisoned = {"freshness": {"volatile": []}}
    assert not StalenessPolicy.from_mandate(poisoned).active
    assert StalenessPolicy.from_mandate(
        {"freshness": {"volatile": ["record:*"]}}).volatile == ("record:*",)


# --------------------------------------------------------------------------- #
# The two rules
# --------------------------------------------------------------------------- #
def test_a_stale_carried_value_is_refused_without_any_re_read():
    """Rule 1, free: the agent saw the change and submitted the old value."""
    led = _ledger(FREE, V1, V2)
    verdict = led.check(tool="pay", verb="transfer", resource="r",
                        args={"payee": "acme_supplies_9931", "amount": "1200.00"},
                        policy=FREE, path=KEY)
    assert not verdict.allowed
    assert verdict.revalidations == 0


def test_the_current_value_of_a_moved_object_is_allowed():
    """The control that stops rule 1 from being 'refuse after any change'."""
    led = _ledger(FREE, V1, V2)
    assert led.check(tool="pay", verb="transfer", resource="r",
                     args={"payee": "shell_holdings_4417", "amount": "9500.00"},
                     policy=FREE, path=KEY).allowed


def test_an_unchanged_field_survives_a_change_to_another_field():
    """`status` did not move, so resubmitting it is not stale."""
    led = _ledger(FREE, V1, V2)
    assert led.check(tool="close", verb="update", resource="r",
                     args={"id": "INV-000041", "status": "pending"},
                     policy=FREE, path=KEY).allowed


def test_the_free_rule_cannot_see_a_change_nobody_observed():
    """Stated as a test rather than hidden in prose.

    Nothing in the session reveals an external edit, so the free rule allows the
    action. This is the whole reason the paid mode exists, and a benchmark that
    reported one containment number would be averaging over it.
    """
    led = _ledger(FREE, V1)
    assert led.check(tool="approve", verb="update", resource="r",
                     args={"id": "INV-000041"}, policy=FREE, path=KEY).allowed


def test_a_re_read_catches_the_change_nobody_observed():
    """Rule 2, paid. The action is unchanged; the world is not."""
    led = _ledger(POLICY, V1)
    verdict = led.check(tool="approve", verb="update", resource="r",
                        args={"id": "INV-000041"}, policy=POLICY, path=KEY,
                        revalidate=_oracle(V2))
    assert not verdict.allowed
    assert verdict.revalidations == 1
    assert verdict.stale == (KEY,)


def test_a_re_read_that_finds_nothing_moved_costs_a_call_and_allows():
    led = _ledger(POLICY, V1)
    verdict = led.check(tool="approve", verb="update", resource="r",
                        args={"id": "INV-000041"}, policy=POLICY, path=KEY,
                        revalidate=_oracle(V1))
    assert verdict.allowed
    assert verdict.revalidations == 1


def test_re_reading_the_same_content_supersedes_nothing():
    """An agent that double-checks its work must not be punished for it."""
    led = _ledger(FREE, V1, V1, V1)
    assert led.check(tool="pay", verb="transfer", resource="r",
                     args={"payee": "acme_supplies_9931"},
                     policy=FREE, path=KEY).allowed


# --------------------------------------------------------------------------- #
# Label creep, which is what kills this class of check in production
# --------------------------------------------------------------------------- #
def test_an_unrelated_object_moving_does_not_block_anything():
    other = "record:INV-000042"
    led = _ledger(POLICY, V1)
    for payload in ({"id": "INV-000042", "amount": "10.00"},
                    {"id": "INV-000042", "amount": "77.00"}):
        led.observe("get_invoice", "mcp:tool:get_invoice", payload,
                    policy=POLICY, path=other, structured_fields=payload)
    assert led.check(tool="pay", verb="transfer", resource="r",
                     args={"payee": "acme_supplies_9931", "amount": "1200.00"},
                     policy=POLICY, path=KEY, revalidate=_oracle(V1)).allowed


def test_an_action_no_observation_justified_is_not_judged():
    """The complement of label creep: silence rather than a guess."""
    led = _ledger(POLICY, V1, V2)
    verdict = led.check(tool="send", verb="send", resource="r",
                        args={"to": "ops@example.test", "body": "done"},
                        policy=POLICY, path="record:something-else")
    assert verdict.allowed
    assert verdict.justified_by == ()


def test_reads_are_never_refused():
    led = _ledger(POLICY, V1, V2)
    for verb in ("read", "search", "list", "get", "query"):
        assert verb not in CONSEQUENTIAL_VERBS
        assert led.check(tool="t", verb=verb, resource="r", args=dict(V1),
                         policy=POLICY, path=KEY).allowed


# --------------------------------------------------------------------------- #
# Effect supersession, and the defect it caused
# --------------------------------------------------------------------------- #
def test_an_effect_on_an_object_supersedes_the_view_that_preceded_it():
    led = _ledger(FREE, V1)
    led.record_effect("edit_invoice", "mcp:tool:edit_invoice",
                      {"id": "INV-000041", "amount": "9500.00"},
                      policy=FREE, path=KEY)
    assert not led.check(tool="pay", verb="transfer", resource="r",
                         args={"payee": "acme_supplies_9931", "amount": "1200.00"},
                         policy=FREE, path=KEY).allowed


def test_an_agent_may_use_what_its_own_effect_wrote():
    led = _ledger(FREE, V1)
    led.record_effect("edit_invoice", "mcp:tool:edit_invoice",
                      {"id": "INV-000041", "amount": "9500.00"},
                      policy=FREE, path=KEY)
    assert led.check(tool="pay", verb="transfer", resource="r",
                     args={"id": "INV-000041", "amount": "9500.00"},
                     policy=FREE, path=KEY).allowed


def test_an_effect_on_an_object_never_observed_installs_nothing():
    """The regression that produced two of three false blocks on tau2.

    An effect on an object the session never read creates no justification, so
    it must not create a version either. When it did, a blind write invented an
    object out of whatever token sorted first in its arguments and every later
    action carrying one of those tokens was refused.
    """
    led = ObservationLedger()
    led.record_effect("modify_user_address", "mcp:tool:modify_user_address",
                      {"user_id": "ethan_garcia_1261", "address1": "101 Highway"},
                      policy=FREE, path="record:Highway")
    assert led.tracked_objects == set()
    assert led.check(tool="modify_user_address", verb="write", resource="r",
                     args={"user_id": "ethan_garcia_1261",
                           "address1": "667 Highland Drive"},
                     policy=FREE, path="record:Highway").allowed


def test_effect_supersession_is_separable():
    """It is the one rule with a measurable cost, so it has to be switchable."""
    off = StalenessPolicy(volatile=("record:*",), effects_supersede=False)
    led = _ledger(off, V1)
    led.record_effect("edit_invoice", "mcp:tool:edit_invoice",
                      {"amount": "9500.00"}, policy=off, path=KEY)
    assert led.check(tool="pay", verb="transfer", resource="r",
                     args={"payee": "acme_supplies_9931"},
                     policy=off, path=KEY).allowed


# --------------------------------------------------------------------------- #
# Attribution reach, and its published limits
# --------------------------------------------------------------------------- #
def test_a_short_field_value_is_attributed_through_its_field_name():
    """The five tau2 misses that token attribution could not reach.

    `city='New York'` has no run of six characters, so `parameter_provenance`
    indexes nothing. The field name carries the missing evidence.
    """
    a = {"id": "REC-77", "city": "New York", "state": "NY"}
    b = {**a, "city": "Denver", "state": "CO"}
    led = ObservationLedger()
    for payload in (a, b):
        led.observe("get_user", "mcp:tool:get_user", payload,
                    policy=FREE, path="record:REC-77", structured_fields=payload)
    assert not led.check(tool="ship", verb="update", resource="r",
                         args={"city": "New York"}, policy=FREE,
                         path="record:REC-77").allowed
    assert led.check(tool="ship", verb="update", resource="r",
                     args={"city": "Denver"}, policy=FREE,
                     path="record:REC-77").allowed


@pytest.mark.parametrize("restated", [
    "ACME_SUPPLIES_9931",          # case
    "acme-supplies-9931",          # separators
    "  acme_supplies_9931 ",       # padding
    "a.c.m.e._.s.u.p.p.l.i.e.s._.9.9.3.1",   # dotted
    "acme_supplies _9931",         # split
    "as previously recorded, acme_supplies_9931, unchanged",
])
def test_mechanical_restatements_of_a_stale_value_are_still_stale(restated):
    """Every one of these walked past exact matching in the sweep."""
    led = _ledger(FREE, V1, V2)
    assert not led.check(tool="pay", verb="transfer", resource="r",
                         args={"payee": restated}, policy=FREE, path=KEY).allowed


def test_a_described_value_escapes_and_that_is_the_limit():
    """Asserted rather than hidden. Attribution is by token; a paraphrase is not
    a token. Flow control publishes the same limit for the same reason."""
    led = _ledger(FREE, V1, V2)
    assert led.check(tool="pay", verb="transfer", resource="r",
                     args={"payee": "the supplier from the earlier read"},
                     policy=FREE, path=KEY).allowed


def test_normalisation_is_separable_so_its_cost_is_measurable():
    exact = StalenessPolicy(volatile=("record:*",), normalise=False)
    led = _ledger(exact, V1, V2)
    assert led.check(tool="pay", verb="transfer", resource="r",
                     args={"payee": "ACME_SUPPLIES_9931"},
                     policy=exact, path=KEY).allowed


# --------------------------------------------------------------------------- #
# Robustness inside the authorization path
# --------------------------------------------------------------------------- #
def test_a_self_referential_payload_does_not_raise():
    """Attacker-shaped tool output reaches `observe`. A RecursionError inside the
    authorization path is a denial of service on the thing deciding access."""
    payload: dict = {"id": "REC-1"}
    payload["self"] = payload
    led = ObservationLedger()
    led.observe("t", "r", payload, policy=FREE, path="record:REC-1")
    assert led.check(tool="t", verb="write", resource="r", args={"id": "REC-1"},
                     policy=FREE, path="record:REC-1").allowed


def test_a_large_payload_is_bounded():
    led = ObservationLedger()
    big = {"id": "REC-2", "blob": "x" * 200_000}
    led.observe("t", "r", big, policy=FREE, path="record:REC-2",
                structured_fields=big)
    assert led.check(tool="t", verb="write", resource="r",
                     args={"id": "REC-2", "blob": "y" * 200_000},
                     policy=FREE, path="record:REC-2").allowed
