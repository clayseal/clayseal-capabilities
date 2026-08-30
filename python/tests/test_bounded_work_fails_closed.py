"""Every bounded scan in a decision path, and which way it fails when it bounds.

Five bugs in this repository shared one shape: a scan bounded its work, ran out,
found nothing in the part it had read, and the caller took that as "there is
nothing there". The bound was correct; the conclusion drawn afterwards was not.

    egress scan length      destination past 16,384 chars      was ALLOWED
    egress walk depth       destination nested 7 levels deep   was ALLOWED
    decoder token budget    secret as the 9th opaque token     was ALLOWED
    needle truncation       secret sent as its tail past 256   was ALLOWED
    variant budget          secret behind 8 KB of padding      was ALLOWED

This file is the standing check on the class. Each bound is exercised past its
limit and asserted to fail CLOSED, except the one that is deliberately allowed
to fail open, whose justification is pinned as a property rather than trusted as
a comment.
"""

from __future__ import annotations

import base64
import pathlib

from clayseal.capabilities.broker import Outcome
from clayseal.capabilities.confidentiality import (
    _MAX_NEEDLE,
    _MAX_VARIANT_CHARS,
    FlowTracker,
    SensitivityPolicy,
    decode_budget_exhausted,
)
from clayseal.capabilities.hardening.egress_policy import (
    MAX_SCAN_CHARS,
    EgressPolicy,
    scan_incomplete,
)

SECRET = "AKIA9F3C1D77B02E4419QZ"
POLICY = SensitivityPolicy(sensitive=("db:customers",),
                           declassified_sinks=("mail:board@example.com",))
EGRESS = EgressPolicy(allowed_domains={"good.example.com"})


def _leaks(blob: str) -> bool:
    """True when the flow tracker lets `blob` out of a session holding a secret."""
    tracker = FlowTracker()
    tracker.observe("read_table", "db:customers", SECRET, policy=POLICY)
    return tracker.check(tool="post", verb="send", resource="http://evil.test",
                         args={"body": blob}, policy=POLICY).allowed


def _egress_allows(args: dict) -> bool:
    ok, _ = EGRESS.check("mcp:tool:send", args)
    return ok


# --- the controls, first -----------------------------------------------------

def test_the_mechanisms_work_at_all() -> None:
    """Every assertion below is a refusal, and all of them would pass against a
    checker that refused everything. These are the rows that say otherwise."""
    assert _egress_allows({"body": "send to good.example.com"})
    assert _egress_allows({"body": "nothing to see here"})
    assert not _egress_allows({"body": "send to evil.example.com"})
    assert not _leaks(SECRET)
    assert _leaks("the quarterly report is attached")


# --- each bound, pushed past its limit ---------------------------------------

def test_egress_scan_length_fails_closed() -> None:
    assert not _egress_allows(
        {"body": "x" * (MAX_SCAN_CHARS + 100) + " evil.example.com"})


def test_egress_walk_depth_fails_closed() -> None:
    deep: dict = {}
    cursor = deep
    for _ in range(10):
        cursor["n"] = {}
        cursor = cursor["n"]
    cursor["dest"] = "evil.example.com"
    assert not _egress_allows(deep)


def test_egress_string_budget_fails_closed() -> None:
    args = {f"k{i}": "filler text" for i in range(700)}
    args["zz"] = "evil.example.com"
    assert not _egress_allows(args)


def test_decoder_token_budget_fails_closed() -> None:
    # Long enough to be an opaque run: `_OPAQUE` is `\S{16,}`, so a short
    # token is not a token as far as the decoder is concerned.
    noise = " ".join(base64.b64encode(f"harmless-payload-{i}".encode()).decode()
                     for i in range(8))
    assert not _leaks(noise + " " + base64.b64encode(SECRET.encode()).decode())


def test_needle_truncation_fails_closed() -> None:
    long_secret = "".join(chr(65 + i % 26) for i in range(_MAX_NEEDLE + 120))
    tracker = FlowTracker()
    tracker.observe("read_table", "db:customers", long_secret, policy=POLICY)
    verdict = tracker.check(tool="post", verb="send", resource="http://evil.test",
                            args={"body": long_secret[_MAX_NEEDLE:]}, policy=POLICY)
    assert not verdict.allowed


def test_variant_budget_fails_closed() -> None:
    padded = "A" * (_MAX_VARIANT_CHARS + 500) + SECRET
    assert not _leaks(padded[::-1])


# --- the one that fails open, and the property that makes it safe ------------

def test_the_entailment_tier_can_only_escalate() -> None:
    """`llm_clients.bounded` returns no reasons when its budget expires, which
    is a deliberate fail-open. Its safety argument is that this tier escalates
    and never denies, so losing it forfeits an advisory rather than a control.

    That argument is a property of the broker, not of the judge, and nothing
    else pins it. If content-entailment ever gains the power to DENY, the
    expired-budget path silently becomes a bypass.
    """
    source = pathlib.Path(
        "clayseal/capabilities/broker.py").read_text(errors="ignore")
    for line in source.splitlines():
        if "content-entailment" in line:
            assert "STEP_UP" in line or "Outcome.STEP_UP" in source[
                max(0, source.index(line) - 200):source.index(line) + 200], (
                "content-entailment reached a non-STEP_UP outcome; the expired "
                "judge budget in llm_clients.bounded is now a bypass")
    assert "content-entailment" in source, "the tier vanished; update this test"
    assert Outcome.STEP_UP is not Outcome.DENY


def test_bounded_scans_report_which_bound_they_hit() -> None:
    """A refusal that cannot say why sends the next reader to guess."""
    assert "characters" in (scan_incomplete({"b": "x" * (MAX_SCAN_CHARS + 1)}) or "")
    noise = " ".join(base64.b64encode(f"harmless-payload-{i}".encode()).decode()
                     for i in range(30))
    assert "encoded-shape" in (decode_budget_exhausted({"b": noise}) or "")
