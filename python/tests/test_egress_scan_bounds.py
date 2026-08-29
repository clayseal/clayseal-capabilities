"""A bounded scan that runs out of budget must not report "clean".

`egress_policy` bounds its walk over attacker-reachable arguments so a huge or
deeply nested one costs a bounded amount of work. That is correct. What was
wrong is what happened when a bound bound: the walk stopped, found no
destination in the part it had read, and the caller took that as "there is no
destination". Both limits were a one-argument bypass of the entire egress
floor, needing no cleverness:

    {"body": "x" * 16_484 + " evil.example.com"}              -> ALLOWED
    {"n": {"n": ... {"dest": "evil.example.com"}}}            -> ALLOWED

while the same address in a short flat argument was refused.

Failing closed was measured before it was chosen: 0 of 10,716 benign events
across seven corpora carry an argument that exceeds either bound.
"""

from __future__ import annotations

import pytest

from clayseal.capabilities.hardening.egress_policy import (
    MAX_SCAN_CHARS,
    EgressPolicy,
    scan_incomplete,
)

POLICY = EgressPolicy(allowed_domains={"good.example.com"})


def _allowed(args: dict) -> bool:
    ok, _ = POLICY.check("mcp:tool:send", args)
    return ok


def test_an_ordinary_disallowed_destination_is_refused() -> None:
    """Control: the checker works at all."""
    assert not _allowed({"body": "send to evil.example.com"})


def test_an_ordinary_allowed_destination_passes() -> None:
    """Control: this is not a policy that refuses everything.

    Every test below asserts a refusal, and all of them would pass against a
    deny-all. This is the row that says the others mean something.
    """
    assert _allowed({"body": "send to good.example.com"})
    assert _allowed({"body": "nothing to see"})


def test_a_destination_past_the_scan_length_is_not_allowed() -> None:
    args = {"body": "x" * (MAX_SCAN_CHARS + 100) + " evil.example.com"}
    assert not _allowed(args)


def test_a_destination_below_the_depth_limit_is_not_allowed() -> None:
    deep: dict = {}
    cursor = deep
    for _ in range(10):
        cursor["n"] = {}
        cursor = cursor["n"]
    cursor["dest"] = "evil.example.com"
    assert not _allowed(deep)


def test_a_destination_past_the_string_budget_is_not_allowed() -> None:
    args = {f"k{i}": "filler text" for i in range(700)}
    args["zz"] = "evil.example.com"
    assert not _allowed(args)


@pytest.mark.parametrize("args", [
    {"body": "short and flat"},
    {"a": {"b": {"c": "still shallow"}}},
    {"items": [{"url": "https://good.example.com/x"}]},
])
def test_arguments_within_the_bounds_are_reported_scannable(args: dict) -> None:
    """Control: `scan_incomplete` must not fire on ordinary arguments.

    If it did, the refusals above would be proving nothing about the bounds.
    """
    assert scan_incomplete(args) is None
    assert _allowed(args)


def test_the_reason_names_which_bound_was_hit() -> None:
    long_reason = scan_incomplete({"b": "x" * (MAX_SCAN_CHARS + 1)})
    deep: dict = {"n": {"n": {"n": {"n": {"n": {"n": {"n": "x"}}}}}}}
    assert long_reason and "characters" in long_reason
    deep_reason = scan_incomplete(deep)
    assert deep_reason and "nested" in deep_reason


def test_a_named_destination_still_reports_itself_rather_than_the_bound() -> None:
    """Order matters: a destination the scan DID see must be named.

    Refusing an oversized argument with "undecidable" when the disallowed
    address was right there in the first field would make the deny reasons
    useless for debugging.
    """
    args = {"to": "evil.example.com", "body": "x" * (MAX_SCAN_CHARS + 100)}
    ok, why = POLICY.check("mcp:tool:send", args)
    assert not ok
    assert "evil.example.com" in why, why
