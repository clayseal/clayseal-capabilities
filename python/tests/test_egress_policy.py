"""Egress policy: the enumerated-recipient gap.

A mandate can name exact recipients and a domain at once. The domain is the
broader grant, and it used to win, so declaring the narrower policy did nothing.
"""
from agentauth.capabilities.hardening.egress_policy import EgressPolicy


# --------------------------------------------------------------------------- #
# An enumerated recipient list must not be widened by a domain grant
# --------------------------------------------------------------------------- #
def _mailbox_policy():
    return EgressPolicy(
        bind_recipients=True, allow_all=False,
        allowed_domains={"acme-internal.com"},
        allowed_recipients={"finance-reports@acme-internal.com"})


def test_the_named_mailbox_is_allowed():
    ok, _ = _mailbox_policy().check(
        "mcp:tool:send_email",
        {"to": "finance-reports@acme-internal.com", "body": "payroll"})
    assert ok


def test_a_different_mailbox_on_an_allowed_domain_is_refused():
    """`same-domain-wrong-mailbox`: the specific declaration used to lose.

    `extract_recipients` returns opaque identifiers only, so an email address
    yields nothing from it, and the domain loop had already accepted the address
    on the strength of its domain. A mandate that enumerated exact recipients
    had that enumeration silently ignored, declaring the narrower policy did
    nothing at all. Payroll addressed to all-hands@ on the same domain was
    allowed.
    """
    ok, reason = _mailbox_policy().check(
        "mcp:tool:send_email",
        {"to": "all-hands@acme-internal.com", "body": "PAYROLL: Ada=..."})
    assert not ok
    assert "not on allow-list" in reason


def test_an_off_domain_address_is_still_refused_by_the_domain_check():
    ok, _ = _mailbox_policy().check(
        "mcp:tool:send_email", {"to": "someone@evil.test", "body": "x"})
    assert not ok


def test_a_policy_naming_no_addresses_is_unchanged():
    """Gated deliberately: a policy listing only opaque identifiers, or none,
    keeps its previous behaviour, so this cannot narrow an existing deployment
    that never enumerated an address."""
    policy = EgressPolicy(bind_recipients=True, allow_all=False,
                          allowed_domains={"acme-internal.com"},
                          allowed_recipients=set())
    ok, _ = policy.check("mcp:tool:send_email",
                         {"to": "anyone@acme-internal.com", "body": "x"})
    assert ok


def test_the_recipient_check_ignores_addresses_in_the_body():
    """Only destination-shaped fields reach the new recipient check.

    `extract_email_addresses` reads destination keys, never message bodies, so a
    report whose text mentions customer addresses is not treated as addressed to
    them. Asserted directly rather than through `check`, because the DOMAIN loop
    has a separate and pre-existing behaviour, see the test below.
    """
    from agentauth.capabilities.hardening.egress_policy import (
        extract_email_addresses,
    )

    args = {"to": "finance-reports@acme-internal.com",
            "body": "Ada <ada@personal.example>, Bo <bo@personal.example>"}
    assert extract_email_addresses(args) == ["finance-reports@acme-internal.com"]


def test_the_domain_check_does_read_the_body_and_this_is_pre_existing():
    """Documented, not endorsed.

    `extract_destinations` scans the whole argument blob, so a domain mentioned
    anywhere in a message body is treated as an egress destination. An internal
    mail whose text quotes customer addresses is refused for a domain it is not
    being sent to.

    Measured on BPL `bulk-exfil`: the benign twin mails the customer sheet to an
    INTERNAL address and is refused for `personal.example`, a domain appearing
    only in the body. This is one false block out of 79 in that sweep, so it is
    not the dominant friction, but it is real and it is the content/recipient
    confusion that makes a control untrustworthy on live traffic.

    Pinned so a fix shows up here as a change rather than as a silently better
    number. Fixing it means separating "where is this going" from "what does it
    say", which is a bigger change than this test.
    """
    policy = _mailbox_policy()
    ok, reason = policy.check(
        "mcp:tool:send_email",
        {"to": "finance-reports@acme-internal.com",
         "body": "Ada <ada@personal.example>"})
    assert not ok
    assert "personal.example" in reason
