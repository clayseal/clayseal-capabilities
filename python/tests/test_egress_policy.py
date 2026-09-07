"""Egress policy: the enumerated-recipient gap.

A mandate can name exact recipients and a domain at once. The domain is the
broader grant, and it used to win, so declaring the narrower policy did nothing.
"""
from clayseal.capabilities.hardening.egress_policy import EgressPolicy


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
    assert "egress.recipients" in reason


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
    from clayseal.capabilities.hardening.egress_policy import (
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


# --------------------------------------------------------------------------- #
# The same declaration must bind on BOTH paths
#
# `check` and `check_with_provenance` are alternatives, not layers: `broker.py`
# calls the second whenever provenance is enabled and the first otherwise, so
# whichever one is missing a rule is missing it for that whole deployment. The
# enumerated-recipient block above lived only in `check`, which is the path a
# deployment takes when it has NO provenance. `DeployableStack` enables
# provenance, so the product path dropped the narrower declaration and fell back
# to the domain. On identical arguments the two disagreed outright:
#
#     check()                 deny: recipient 'all-hands@...' not on allow-list
#     check_with_provenance() allow: egress within policy
#
# The BPL scenario named for this, `same-domain-wrong-mailbox`, constructs
# `SessionBroker(goal=..., scope=None, egress=egress)` with no provenance, so it
# exercised the path that was already correct and reported containment for a
# configuration the product does not run. That is the whole reason the gap
# survived having a test and a benchmark scenario both pointed at it.
#
# These tests take the verdict from both paths on one input, so a rule that
# reaches only one of them fails here rather than in a deployment.
# --------------------------------------------------------------------------- #
def _both_paths(policy, args, *, goal_named=frozenset()):
    """(check verdict, check_with_provenance verdict), normalised to allow/deny."""
    from clayseal.capabilities.parameter_provenance import ParameterProvenance

    ok, _ = policy.check("mcp:tool:send_email", args)
    verdict, _ = policy.check_with_provenance(
        "mcp:tool:send_email", args,
        provenance=ParameterProvenance(), goal_named_objects=set(goal_named))
    return ("allow" if ok else "deny"), verdict


def test_the_named_mailbox_is_allowed_on_both_paths():
    assert _both_paths(
        _mailbox_policy(),
        {"to": "finance-reports@acme-internal.com", "body": "payroll"},
    ) == ("allow", "allow")


def test_the_wrong_mailbox_is_refused_on_both_paths():
    """The regression this section exists for.

    An ungrounded address, which is what an injected recipient is before the
    agent has read anything, must not reach a send on either path.
    """
    assert _both_paths(
        _mailbox_policy(),
        {"to": "all-hands@acme-internal.com", "body": "PAYROLL: Ada=..."},
    ) == ("deny", "deny")


def test_a_wrong_mailbox_names_recipients_on_the_provenance_path():
    """Agents were reading the provenance sentence as a broken allow-list."""
    from clayseal.capabilities.parameter_provenance import ParameterProvenance

    verdict, reason = _mailbox_policy().check_with_provenance(
        "mcp:tool:send_email",
        {"to": "all-hands@acme-internal.com", "body": "PAYROLL: Ada=..."},
        provenance=ParameterProvenance(),
    )
    assert verdict == "deny", reason
    assert "egress.recipients" in reason
    assert "appears in no observation" not in reason


def test_a_policy_naming_no_addresses_is_unchanged_on_both_paths():
    """The gate stays where it was: enumerate no address and nothing narrows.

    Pinned on both paths so the fix above cannot tighten a deployment that never
    declared a recipient list.
    """
    policy = EgressPolicy(bind_recipients=True, allow_all=False,
                          allowed_domains={"acme-internal.com"},
                          allowed_recipients=set())
    assert _both_paths(
        policy, {"to": "anyone@acme-internal.com", "body": "x"},
    ) == ("allow", "allow")


def test_a_grounded_wrong_mailbox_steps_up_rather_than_denying():
    """Provenance earns supervision on the address path too.

    The point of the provenance path is that a recipient the agent legitimately
    discovered at runtime is recoverable under a person rather than refused
    outright. That has to hold for an enumerated-address miss as well, otherwise
    turning on the narrower declaration would convert every runtime-discovered
    recipient into a hard denial.
    """
    from clayseal.capabilities.parameter_provenance import ParameterProvenance

    provenance = ParameterProvenance()
    provenance.record_observation(
        "lookup_directory",
        "Finance AP contact",
        structured_fields={"email": "finance-ap@acme-internal.com"},
        goal_named=True,
        containing_object="directory",
    )
    verdict, reason = _mailbox_policy().check_with_provenance(
        "mcp:tool:send_email",
        {"to": "finance-ap@acme-internal.com", "body": "payroll"},
        provenance=provenance,
        goal_named_objects={"directory"},
    )
    assert verdict == "step_up", reason
    assert "egress.recipients" in reason
    assert "appears in no observation" not in reason
