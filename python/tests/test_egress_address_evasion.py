"""A destination that lies about where it routes must not clear the allow-list.

`ops@acme-internal.com@evil.test` is delivered to **evil.test**: RFC 5321 routes
on the last `@` and so does every mailer. The address regex stopped at the
second `@`, because `@` is not in its host character class, so it extracted
`acme-internal.com`, matched the allow-list, and the real destination was never
shown to the check.
"""
from __future__ import annotations

import pytest

from clayseal.capabilities.hardening.egress_policy import (
    EgressPolicy,
    extract_destinations,
)

ALLOWED = "acme-internal.com"


def _policy():
    return EgressPolicy(allowed_domains={ALLOWED})


@pytest.mark.parametrize("destination", [
    f"ops@{ALLOWED}@evil.test",              # allowed domain first
    f"ops@evil.test@{ALLOWED}",              # allowed domain last
    f"a@b.test@c.test@{ALLOWED}",            # several hops
])
def test_a_multi_at_address_cannot_hide_its_routing_host(destination):
    allowed, reason = _policy().check("mcp:tool:send_email", {"to": destination})
    assert not allowed, reason
    # The host it would really route to has to be visible to the check, not
    # merely absent from the allow-list by luck.
    assert destination.rsplit("@", 1)[-1] in extract_destinations(
        "x", {"to": destination})


@pytest.mark.parametrize("destination", [
    f"ops@{ALLOWED}",
    f"ops+tag@{ALLOWED}",
    f"a@{ALLOWED}, b@{ALLOWED}",
    f"a@{ALLOWED}; b@{ALLOWED}",
])
def test_ordinary_addresses_and_recipient_lists_still_pass(destination):
    """A list of recipients has several `@` between them and must be unaffected."""
    allowed, reason = _policy().check("mcp:tool:send_email", {"to": destination})
    assert allowed, reason


def test_a_list_with_one_bad_recipient_is_refused():
    allowed, _ = _policy().check(
        "mcp:tool:send_email", {"to": f"a@{ALLOWED}, b@evil.test"})
    assert not allowed
