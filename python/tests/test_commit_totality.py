"""The commit-token verifier is total, and exactly one input verifies.

Every other control in this repo sits above the commit token. If the verifier can
be made to say yes when the authority, tool, resource, arguments, query or expiry
is wrong, nothing above it matters. So the property is not a list of scenarios:
mutate ANY field of the token or the context to ANY value, and verification must
fail.
"""
from __future__ import annotations

from dataclasses import replace

import pytest

from clayseal.capabilities.commit import (
    CommitToken,
    SignedCommitToken,
    parse_signed_commit_token,
)
from benchmarks.stress_commit import _pair, _verify, run


def test_no_mutation_of_the_token_or_context_ever_verifies():
    """336 verifications across every field x a hostile value corpus.

    The positive result this pins: token/context binding, replay defense,
    expiry and signer pinning are all sound. This test is the regression guard
    on that, not a hunt.
    """
    report = run()
    assert not report["BASELINE"], report["BASELINE"]
    assert not report["NO_MUTATION_VERIFIES"], report["NO_MUTATION_VERIFIES"]
    assert not report["REPLAY_IS_REFUSED"], report["REPLAY_IS_REFUSED"]
    assert report["checks"] > 300, report["checks"]


def test_the_verifier_never_raises():
    """A verifier may deny; it may not throw.

    Two defects closed here. ``CommitToken.to_dict`` coerces the integer fields
    with ``int()`` and is the FIRST thing the verifier calls, ahead of the
    signature check, so a token holding ``authority_version='x'`` raised
    ``ValueError`` from inside the verifier rather than being rejected by it.
    And a non-string ``action_name`` on the caller-supplied context raised
    ``AttributeError`` from ``.rsplit``.
    """
    report = run()
    assert not report["NEVER_RAISES"], report["NEVER_RAISES"]


# --------------------------------------------------------------------------- #
# The invalid states, now unrepresentable or refused.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad", ["x", "", None, [1], {"a": 1}, "NaN", float("inf")])
def test_a_token_that_cannot_be_serialized_cannot_be_built(bad):
    """Validated in ``__post_init__`` rather than left to explode in the
    verifier. A type that permits a state whose only expression is an exception
    deep inside a security check is the wrong shape."""
    signed, _, _ = _pair()
    with pytest.raises(ValueError):
        replace(signed.token, authority_version=bad)


def test_a_malformed_context_is_denied_rather_than_crashing():
    signed, ctx, trusted = _pair()
    broken = replace(ctx, action=replace(ctx.action, action_name=None))
    ok, reason = _verify(signed, broken, trusted)
    assert not ok
    assert "action_name" in (reason or "")


# --------------------------------------------------------------------------- #
# The wire boundary.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("junk", [None, "nope", [1], 42, b"bytes", 3.5])
def test_the_wire_parser_returns_a_verdict_for_any_input(junk):
    """``from_dict`` is a constructor for TRUSTED data and raises three different
    exception types on hostile JSON. ``parse_signed_commit_token`` is the
    boundary: it returns ``(None, reason)`` and never raises, for anything."""
    token, reason = parse_signed_commit_token(junk)
    assert token is None
    assert reason


def test_the_wire_parser_rejects_each_malformed_field():
    signed, _, _ = _pair()
    wire = signed.to_dict()
    import copy

    for mutate in (
        lambda r: r["token"].__setitem__("authority_version", "PWNED"),
        lambda r: r["token"].__setitem__("permit_epoch", "NaN"),
        lambda r: r["token"].pop("token_id", None),
        lambda r: r.pop("signature", None),
        lambda r: r.__setitem__("token", "not-a-dict"),
    ):
        raw = copy.deepcopy(wire)
        mutate(raw)
        token, reason = parse_signed_commit_token(raw)
        assert token is None, raw
        assert reason


def test_a_well_formed_token_still_round_trips():
    """The guards must not break the path that matters."""
    signed, ctx, trusted = _pair()
    token, reason = parse_signed_commit_token(signed.to_dict())
    assert reason is None
    assert token is not None
    ok, why = _verify(token, ctx, trusted)
    assert ok, why


def test_from_dict_is_still_the_trusted_constructor():
    """Deliberately unchanged: it raises, and its docstring says so. Callers
    holding trusted data keep the strict behaviour."""
    with pytest.raises((KeyError, ValueError, TypeError)):
        SignedCommitToken.from_dict({"token": {}, "signature": {}})
    assert issubclass(CommitToken, object)
