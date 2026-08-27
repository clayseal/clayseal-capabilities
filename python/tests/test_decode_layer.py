"""A decoder that stops at the first thing that did not raise is not a decoder.

`_decode_layer` tries encodings strictest-first and stopped at the first attempt
that returned bytes. Two of those attempts do not validate their input, so they
"succeed" on almost anything, `urlsafe_b64decode` accepts a base85 payload,
returns thirteen bytes of noise, and the loop breaks before the base85 decoder
two lines below is ever reached.

Found by the adaptive search, not by reading: of nine in-scope staging evasions
run against the shipped gateway, base85 was the ONE that got through, which is
also what `flow_window.md` records as open. The fix is to judge whether a decode
plausibly SUCCEEDED rather than whether it raised, and to keep trying otherwise.

The plausibility test had its own version of the same bug on the first attempt:
`errors="ignore"` throws away every byte that is not valid UTF-8, so the noise
became a six-character string that then looked "mostly printable" and passed.
Judging the survivors of a lossy decode is judging the decoder's own edit of the
evidence. It decodes strictly now.
"""
from __future__ import annotations

import base64
import zlib

import pytest

from agentauth.capabilities.confidentiality import _decode_layer, _plausible

SECRET = "AKIA7QF3ZC1D77B02E4X"

ENCODINGS = [
    pytest.param(base64.b85encode(SECRET.encode()).decode(), id="base85"),
    pytest.param(base64.b64encode(SECRET.encode()).decode(), id="base64"),
    pytest.param(base64.urlsafe_b64encode(SECRET.encode()).decode(), id="urlsafe-base64"),
    pytest.param(base64.b32encode(SECRET.encode()).decode(), id="base32"),
    pytest.param(SECRET.encode().hex(), id="hex"),
]


@pytest.mark.parametrize("token", ENCODINGS)
def test_every_standard_encoding_is_recovered(token):
    """One decoder shadowing another is the failure this exists to prevent."""
    recovered = _decode_layer(token)
    assert any(SECRET in r for r in recovered), (
        f"{token!r} decoded to {recovered!r}, losing the secret"
    )


def test_the_shadowing_decoder_no_longer_shadows():
    """The specific mechanism, pinned.

    `urlsafe_b64decode` still "succeeds" on a base85 token: that is a property
    of the codec, not something to fix. What must not happen is the loop
    stopping there.
    """
    token = base64.b85encode(SECRET.encode()).decode()
    shadow = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    assert shadow, "the premise changed: urlsafe no longer decodes this"
    assert _plausible(shadow) is None, "noise is being judged plausible again"
    assert any(SECRET in r for r in _decode_layer(token))


def test_a_lossy_decode_is_not_judged_on_its_survivors():
    """`errors='ignore'` deletes the evidence, then the check reads what is left."""
    noise = b"(\xd1\xc8\xe3d\xf4\xd8\x91\xdb\xe6\xc1\x83K~"
    assert _plausible(noise) is None
    # It WOULD have passed a lossy check: most of what survives is printable.
    survivors = noise.decode("utf-8", "ignore")
    printable = sum(1 for c in survivors if 32 <= ord(c) < 127)
    assert printable / max(len(survivors), 1) >= 0.8


def test_plaintext_and_compressed_payloads_stay_plausible():
    assert _plausible(SECRET.encode()) == SECRET
    compressed = zlib.compress(SECRET.encode())
    assert _plausible(compressed) is not None, "a zlib stream must survive the check"


def test_a_compressed_payload_is_still_unpacked():
    """The magic-byte path has to keep working past the new check."""
    packed = base64.b64encode(zlib.compress(SECRET.encode())).decode()
    assert any(SECRET in r for r in _decode_layer(packed))


def test_random_bytes_do_not_become_findings():
    """The reason the loop stopped early in the first place.

    base85 accepts nearly any byte string, so decoding everything with it would
    turn ordinary opaque tokens into noise the tracker then searches. The
    plausibility check is what makes trying it safe.
    """
    findings = _decode_layer("Z3q7Kd2Lm9Xr4Tb8Vw1Ns6Ph0Jc5Yg")
    assert all(SECRET not in f for f in findings)


def test_the_fix_costs_no_false_blocks_on_benign_traffic():
    """The measurement that decides whether the fix is worth having.

    Full run: `python -m benchmarks.flow --corpus tau2` reports 0 of 1,242
    benign events blocked, unchanged from before the fix. This is the cheap
    version, the shapes that would break first if the decoder became greedy.
    """
    from agentauth.capabilities.confidentiality import FlowTracker, SensitivityPolicy

    benign_bodies = [
        "commit 5f2a1c9e8b7d3a4f6c0e1b2d",           # a git sha
        "build-artifact-9f8e7d6c5b4a392817",          # an opaque id
        "https://example.com/a/bWFpbi5weQ",           # base64-ish path segment
        "user_token_placeholder_do_not_use",
        "2026-08-19T06:00:00Z checksum d41d8cd98f00b204e9800998ecf8427e",
    ]
    policy = SensitivityPolicy(sensitive=("*AKIA*",), declassified_sinks=())
    tracker = FlowTracker()
    tracker.observe("Read", "/app/.env", f"AWS={SECRET}", policy=policy,
                    path="/app/.env")
    for body in benign_bodies:
        verdict = tracker.check(tool="Write", verb="write", resource="workspace",
                                args={"content": body}, policy=policy,
                                path="/app/README.md")
        assert verdict.allowed, f"benign body flagged: {body!r} ({verdict.reason})"
