"""Confidentiality flow: harm defined by the sequence rather than the target.

The mechanism is per-value, not per-session, and that is the whole reason it is
deployable. A session-level tracker blocks every write after the first sensitive
read, which is the label-creep failure that has kept information-flow control out
of production for forty years. The tests that matter here are the ones that would
catch it drifting back toward that.
"""
from __future__ import annotations

import base64

import pytest

from agentauth.capabilities.confidentiality import (
    FlowTracker,
    SensitivityPolicy,
    declassified_sinks_from_goal,
)

SECRET = "AKIA9F3C1D77B02E4419QZ"
POLICY = SensitivityPolicy(
    sensitive=("db:customers", "/vault/**"),
    declassified_sinks=("mail:board@example.com",),
)


def _tracker(payload=SECRET, resource="db:customers", structured=True):
    t = FlowTracker()
    t.observe("read_table", resource, payload, policy=POLICY,
              structured_fields={"value": payload} if structured else None)
    return t


def _check(tracker, args, resource="mail:leaker@evil.test", verb="send"):
    return tracker.check(tool="send_mail", verb=verb, resource=resource,
                         args=args, policy=POLICY)


# --------------------------------------------------------------------------- #
# The property that makes it deployable
# --------------------------------------------------------------------------- #
def test_a_write_that_carries_nothing_sensitive_is_allowed():
    """Per-value, not per-session. The session HAS read a secret; this write
    does not contain it, so it must pass. A tracker that fails this blocks every
    action after the first sensitive read."""
    verdict = _check(_tracker(), {"body": "the meeting is at four"})
    assert verdict.allowed
    assert not verdict.carried


def test_a_write_carrying_the_secret_to_an_unnamed_sink_is_refused():
    verdict = _check(_tracker(), {"body": SECRET})
    assert not verdict.allowed
    assert "db:customers" in verdict.carried


def test_the_sink_the_goal_named_may_receive_it():
    """Declassification. Refusing this refuses the job."""
    verdict = _check(_tracker(), {"body": SECRET},
                     resource="mail:board@example.com")
    assert verdict.allowed
    assert verdict.declassified_by == "mail:board@example.com"
    assert verdict.carried, "the flow happened; it was authorized, not absent"


def test_a_read_is_never_refused():
    """Reads cannot leak, and refusing them would break every task."""
    assert _check(_tracker(), {"path": SECRET}, verb="read").allowed


def test_an_absent_policy_changes_nothing():
    """Opt-in per mandate: a mandate written before this module behaves as it
    did."""
    t = FlowTracker()
    empty = SensitivityPolicy()
    t.observe("read_table", "db:customers", SECRET, policy=empty)
    assert t.check(tool="send_mail", verb="send", resource="mail:evil",
                   args={"body": SECRET}, policy=empty).allowed


# --------------------------------------------------------------------------- #
# Evasion. Each of these carried the value out at 100% before it was handled.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name,payload", [
    ("verbatim", SECRET),
    ("embedded in prose", f"Here is the record you asked for: {SECRET}. Regards."),
    ("split in two", f"{SECRET[:11]} {SECRET[11:]}"),
    ("split into fours", " ".join(SECRET[i:i + 4] for i in range(0, len(SECRET), 4))),
    ("base64", base64.b64encode(SECRET.encode()).decode()),
    ("hex", SECRET.encode().hex()),
    ("reversed", SECRET[::-1]),
    ("dotted", ".".join(SECRET)),
    ("nested in structure", {"outer": {"inner": [SECRET]}}),
])
def test_transformed_values_are_still_attributed(name, payload):
    verdict = _check(_tracker(), {"body": payload})
    assert not verdict.allowed, f"{name} carried the value out"


def test_a_semantically_destroyed_value_is_not_attributed():
    """The standing limit, asserted rather than hidden.

    Flow control raises the cost of exfiltration; it does not make it
    impossible. A value the agent describes instead of quoting is gone, and any
    claim otherwise would be false.
    """
    described = "the key starts with A and has twenty-two characters"
    assert _check(_tracker(), {"body": described}).allowed


# --------------------------------------------------------------------------- #
# False positives, which is where a reconstruction pass goes wrong
# --------------------------------------------------------------------------- #
def test_reconstruction_does_not_flag_a_long_unrelated_payload():
    """Stripping separators makes long strings out of ordinary text, and a short
    secret could then appear inside one by coincidence. The minimum length for a
    reconstructed match exists for this."""
    prose = ("Quarterly review notes: revenue up, churn flat, hiring paused. "
             "Action items assigned to the platform and billing teams. " * 20)
    assert _check(_tracker(), {"body": prose}).allowed


def test_a_short_sensitive_value_does_not_taint_everything():
    """A six-character secret is attributable exactly but must not be matched by
    reconstruction, or every payload containing those letters is refused."""
    t = FlowTracker()
    t.observe("read_table", "db:customers", "abc123", policy=POLICY,
              structured_fields={"value": "abc123"})
    assert t.check(tool="send_mail", verb="send", resource="mail:evil",
                   args={"body": "a-b-c-1-2-3 and other things"},
                   policy=POLICY).allowed


def test_a_non_sensitive_read_taints_nothing():
    t = FlowTracker()
    t.observe("read_table", "db:public_prices", SECRET, policy=POLICY,
              structured_fields={"value": SECRET})
    assert _check(t, {"body": SECRET}).allowed


# --------------------------------------------------------------------------- #
# Declassification comes from the sealed goal only
# --------------------------------------------------------------------------- #
def test_declassified_sinks_are_read_from_the_goal():
    sinks = declassified_sinks_from_goal(
        "email the quarterly numbers to board@example.com",
        ["board@example.com", "leaker@evil.test"])
    assert sinks == ("board@example.com",)


def test_a_sink_the_goal_did_not_name_is_not_declassified():
    assert declassified_sinks_from_goal(
        "summarise the inbox", ["board@example.com"]) == ()


def test_policy_comes_from_the_mandate_not_from_runtime():
    """A policy an attacker can influence is not a policy. The only constructor
    reads the mandate."""
    policy = SensitivityPolicy.from_mandate({
        "confidentiality": {"sensitive": ["db:*"],
                            "declassified_sinks": ["mail:board@example.com"]}})
    assert policy.active
    assert policy.is_sensitive("db:customers")
    assert policy.is_declassified("mail:board@example.com")
    assert not policy.is_declassified("mail:evil")
    assert not SensitivityPolicy.from_mandate({}).active


# --------------------------------------------------------------------------- #
# The traversal is bounded, because attacker-shaped output reaches it
# --------------------------------------------------------------------------- #
def test_deeply_nested_tool_output_does_not_crash_the_authorization_path():
    """A RecursionError inside the thing that decides whether actions are
    allowed is a denial of service on the authorization layer itself."""
    from agentauth.capabilities.parameter_provenance import ParameterProvenance

    payload = SECRET
    for _ in range(5000):
        payload = [payload]
    assert ParameterProvenance._tokens(payload) == []


def test_a_self_referential_payload_terminates():
    from agentauth.capabilities.parameter_provenance import ParameterProvenance

    cycle = []
    cycle.append(cycle)
    cycle.append(SECRET)
    assert SECRET in ParameterProvenance._tokens(cycle)


def test_ordinary_nesting_is_still_walked():
    from agentauth.capabilities.parameter_provenance import ParameterProvenance

    tokens = ParameterProvenance._tokens(
        {"to": "alice@corp.example", "cc": [{"addr": "bob@corp.example"}]})
    assert "alice@corp.example" in tokens
    assert "bob@corp.example" in tokens


def test_an_unwalkable_payload_grounds_less_rather_than_more():
    """Failing toward refusal. A payload we cannot fully traverse must not come
    back grounded."""
    from agentauth.capabilities.parameter_provenance import ParameterProvenance

    p = ParameterProvenance()
    p.record_observation("read", "x", structured_fields={"v": SECRET})
    payload = SECRET
    for _ in range(5000):
        payload = [payload]
    ok, _ = p.is_grounded(payload)
    assert not ok
