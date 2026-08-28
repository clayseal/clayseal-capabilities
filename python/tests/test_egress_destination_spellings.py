"""A destination the policy cannot READ is a destination it cannot DENY.

`EgressPolicy.check` returns True both for "every destination was on the
allow-list" and for "there was no destination to check". `binds()` documents
that. It means any encoding of a host that the extractor fails to recognise is
not refused, it is invisible, and the action carrying it passes the egress floor
untouched.

Five spellings were invisible, each of them one an ordinary HTTP client or
mailer delivers to:

    http://[2001:db8::1]/exfil      bracketed IPv6
    x@аttacker.com                  a Cyrillic homograph of `attacker.com`
    http://intranet/exfil           a single-label host
    http://3405803781/exfil         the integer form of 203.0.113.5
    http://0xCB00710D/exfil         the hexadecimal form

The dotted form `http://203.0.113.5/exfil` was refused throughout, which is what
makes these a gap rather than a stated boundary: the same address in a different
base changed the decision.

The control at the bottom is the part that keeps this file honest. If the
extractor ever starts returning nothing at all, every assertion above it still
passes, because "no destination" reads as allowed.
"""
from __future__ import annotations

import pytest

from clayseal.capabilities.hardening.egress_policy import EgressPolicy, extract_destinations

ALLOWED = "acme-internal.com"


def _policy() -> EgressPolicy:
    return EgressPolicy(allowed_domains={ALLOWED})


# (name, args, the canonical destination the extractor must produce)
BLOCKED_SPELLINGS = [
    ("ipv6_bracketed", {"url": "http://[2001:db8::1]/exfil"}, "2001:db8::1"),
    ("idn_homograph_email", {"to": "x@аttacker.com"}, "xn--ttacker-1fg.com"),
    ("single_label_host", {"url": "http://intranet/exfil"}, "intranet"),
    ("ipv4_decimal", {"url": "http://3405803781/exfil"}, "203.0.113.5"),
    ("ipv4_hex", {"url": "http://0xCB00710D/exfil"}, "203.0.113.13"),
    ("ipv4_dotted_control", {"url": "http://203.0.113.5/exfil"}, "203.0.113.5"),
]


@pytest.mark.parametrize("name,args,expected", BLOCKED_SPELLINGS,
                         ids=[c[0] for c in BLOCKED_SPELLINGS])
def test_every_spelling_of_an_unlisted_destination_is_refused(name, args, expected):
    allowed, reason = _policy().check("tool://send", args)
    assert not allowed, f"{name}: {args} passed the egress floor"
    assert expected in reason, reason


@pytest.mark.parametrize("name,args,expected", BLOCKED_SPELLINGS,
                         ids=[c[0] for c in BLOCKED_SPELLINGS])
def test_the_destination_is_actually_extracted(name, args, expected):
    """Not merely refused: refused *for the right host*.

    A refusal with the destination missing from it would mean some other rule
    fired, and this file would be testing that rule instead.
    """
    assert expected in extract_destinations("tool://send", args)


def test_alternate_bases_canonicalise_to_one_address():
    """Allow-listing an address once has to cover every way of writing it.

    Detecting an IP literal without canonicalising it moves the bypass rather
    than closing it: the deny-list entry and the request would still be
    different strings.
    """
    spellings = ["http://203.0.113.5/x", "http://3405803781/x", "http://0313.0.0161.05/x"]
    extracted = {extract_destinations("tool://send", {"url": s})[0] for s in spellings}
    assert extracted == {"203.0.113.5"}, extracted

    permissive = EgressPolicy(allowed_domains={"203.0.113.5"})
    for s in spellings:
        allowed, reason = permissive.check("tool://send", {"url": s})
        assert allowed, f"{s} was refused despite the address being allow-listed: {reason}"


def test_an_allowed_destination_still_passes():
    """The floor must not have been closed by refusing everything."""
    allowed, reason = _policy().check("tool://send", {"to": f"ops@{ALLOWED}"})
    assert allowed, reason


def test_a_bare_username_is_not_read_as_a_host():
    """The fix admits single-label hosts only when written as a URL.

    A `to` field holding `bob` is a username. `extract_recipients` binds those,
    under `bind_recipients`; reading it as a hostname here would refuse ordinary
    work to close nothing.
    """
    assert extract_destinations("tool://send", {"to": "bob"}) == []
    assert extract_destinations("tool://send", {"account": "ACCT-99213"}) == []


def test_prose_mentioning_a_number_is_not_a_destination():
    """A body is scanned for destinations, so a bare integer must not become one."""
    args = {"to": f"ops@{ALLOWED}", "body": "invoice 3405803781 was paid on 0xCB00710D"}
    allowed, reason = _policy().check("tool://send", args)
    assert allowed, reason


def test_the_extractor_is_not_silently_empty():
    """The control.

    Every assertion above is satisfied by an extractor that returns nothing,
    because an action with no destination passes `check`. This is the one test
    that fails if the mechanism goes inert.
    """
    found = extract_destinations("tool://send", {"to": "attacker@evil.test"})
    assert found == ["evil.test"], found
