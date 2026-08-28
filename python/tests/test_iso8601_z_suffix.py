"""A `Z` expiry must parse on every Python this package claims to support.

`datetime.fromisoformat` did not accept a trailing `Z` until 3.11, and
`requires-python` is `>=3.10`. RFC 3339 spells UTC as `Z`, every mandate schema
here writes one, and the README's own example policy says
`expires_at: 2027-12-31T00:00:00Z`.

On 3.10 the parse raised, and `TaskScope.is_expired` treats an unparseable expiry
as EXPIRED — correctly, since a grant whose validity cannot be established is not
a valid grant. So on the oldest supported Python, **every policy with a `Z`
expiry denied every call**. CI had been red on the 3.10 leg for some time and the
failure read as three broken pattern tests rather than as "the library does not
work on 3.10".

The fail-closed design is why this was a usability catastrophe and not a security
one, and it is also why it hid: a gateway that refuses everything looks like a
gateway that is working, from the inside.

Nine call sites read timestamps and exactly one carried its own
`.replace("Z", "+00:00")`. There is one parser now, and these are its tests.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from clayseal.capabilities.monitor.action import Action
from clayseal.capabilities.policy import compile_policy
from clayseal.core.task_scope import TaskScope
from clayseal.core.timestamps import parse_iso8601, parse_iso8601_utc

ACCEPTED = [
    "2030-01-01T00:00:00Z",
    "2030-01-01T00:00:00z",
    "2030-01-01T00:00:00+00:00",
    "2030-01-01T00:00:00.123456Z",
    "2030-01-01T00:00:00-05:00",
    "2030-01-01T00:00:00",
    "2030-01-01",
]


@pytest.mark.parametrize("value", ACCEPTED)
def test_the_shapes_a_mandate_actually_writes_all_parse(value):
    assert isinstance(parse_iso8601(value), datetime)


def test_a_z_suffix_means_utc():
    assert parse_iso8601("2030-01-01T00:00:00Z").utcoffset().total_seconds() == 0


def test_a_naive_timestamp_is_read_as_utc_where_that_matters():
    """Not as local time, which would silently extend an expiry by the offset."""
    assert parse_iso8601_utc("2030-01-01T00:00:00").tzinfo is timezone.utc
    # An explicit offset is left alone.
    assert parse_iso8601_utc("2030-01-01T00:00:00-05:00").utcoffset().total_seconds() == -18000


def test_unparseable_still_raises():
    """The tri-state callers rely on: a bad timestamp must not become a good one."""
    for bad in ("", "not-a-date", "2030-13-45T99:99:99Z"):
        with pytest.raises(ValueError):
            parse_iso8601(bad)


def test_a_future_z_expiry_does_not_read_as_expired():
    """The bug, at the layer it bit. `is_expired` returns True on a parse
    failure, so this returned True for every `Z` expiry on 3.10."""
    scope = TaskScope(expires_at="2030-01-01T00:00:00Z")
    assert scope.is_expired() is False


def test_a_past_z_expiry_still_reads_as_expired():
    """The control. Every assertion above passes if `is_expired` started
    returning False unconditionally, which would be a fail-OPEN."""
    scope = TaskScope(expires_at="2020-01-01T00:00:00Z")
    assert scope.is_expired() is True


def test_an_unparseable_expiry_still_fails_closed():
    """The property that made this survivable, and must not be lost in fixing it."""
    assert TaskScope(expires_at="whenever").is_expired() is True


def test_a_policy_with_a_z_expiry_authorizes_its_own_tools():
    """End to end, in the shape the README documents."""
    policy = compile_policy({
        "version": 1,
        "goal": {"id": "t", "summary": "look things up"},
        "expires_at": "2030-01-01T00:00:00Z",
        "tools": {"allow": ["get_reservation"], "effects": {"get_reservation": "read"}},
        "paths": {"pathless": ["get_reservation"]},
    })
    gateway = policy.build()
    decision = gateway.authorize(
        Action(0, "get_reservation", "mcp:tool:get_reservation", "read", args={}))
    assert decision.allowed, decision.reasons
