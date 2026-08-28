"""The translation table and the character set have to stay one answer.

`_hosts_in` and `_addresses_in` blank the characters in `_NOT_IN_TOKEN` before
scanning. That was a per-character generator expression, which is the slowest
thing on the decision path for a large argument: 0.7 ms on a 16 KB body against
0.017 ms for `str.translate`. Arguments here are attacker-influenced, so the
difference is whether a 16 KB field costs 1.2 ms or 0.02 ms.

The optimisation introduces the hazard this repository keeps getting bitten by:
one question with two implementations. `_NOT_IN_TOKEN` says which characters
break a token, and `_TOKEN_BLANKS` says it a second time. Adding a character to
the frozenset and forgetting the table would leave the scanner reading a
separator as part of a hostname, silently, with no test failing — the same shape
as the deny-list bypass in `task_scope.py` and the two host parses in
`egress_policy.py` itself.

So the table is derived from the set, and this file asserts they agree rather
than trusting that they do.
"""
from __future__ import annotations

import random
import string

import pytest

from clayseal.capabilities.hardening.egress_policy import (
    _NOT_IN_TOKEN,
    _TOKEN_BLANKS,
    MAX_SCAN_CHARS,
)


def _reference(text: str) -> str:
    """The implementation `str.translate` replaced. The oracle, kept on purpose."""
    return "".join(" " if c in _NOT_IN_TOKEN else c for c in text[:MAX_SCAN_CHARS])


def _current(text: str) -> str:
    return text[:MAX_SCAN_CHARS].translate(_TOKEN_BLANKS)


def test_the_table_covers_exactly_the_character_set():
    """Neither more nor less. A table that blanks a character the set does not
    name would silently split a hostname; one that misses a character the set
    does name would let a separator through as part of one."""
    blanked = {chr(k) for k, v in _TOKEN_BLANKS.items() if v == " "}
    assert blanked == set(_NOT_IN_TOKEN), {
        "in table, not in set": sorted(blanked - set(_NOT_IN_TOKEN)),
        "in set, not in table": sorted(set(_NOT_IN_TOKEN) - blanked),
    }


NAMED_CASES = [
    ("empty", ""),
    ("plain address", "ops@acme-internal.com"),
    ("url with query and fragment", "https://evil.test/x?a=1#frag"),
    ("html wrapping", "<a href='http://x.com'>y</a>"),
    ("separator run", "ops@a.com,bob@b.com;c@d.com"),
    ("adversarial at signs", "@" * 20_000),
    ("adversarial dots", "." * 20_000),
    ("no separators at all", "a" * 20_000),
    ("control characters", "".join(chr(c) for c in (0, 1, 2, 7, 27))),
    ("just below the cap", "x" * (MAX_SCAN_CHARS - 1)),
    ("exactly the cap", "x" * MAX_SCAN_CHARS),
    ("just above the cap", "x" * (MAX_SCAN_CHARS + 1)),
]


@pytest.mark.parametrize("name,text", NAMED_CASES, ids=[c[0] for c in NAMED_CASES])
def test_translate_matches_the_reference(name, text):
    assert _current(text) == _reference(text), name


def test_translate_matches_the_reference_on_random_input():
    """Including non-ASCII, which `str.maketrans` keys by code point and the
    generator compared by membership. Those are the same answer only if the
    table was built from the set."""
    alphabet = string.printable + "".join(
        # Cyrillic a, sharp s, e-acute, a CJK character, an emoji,
        # zero-width space, non-breaking space.
        chr(c) for c in (0x0430, 0x00DF, 0x00E9, 0x4E2D, 0x1F642, 0x200B, 0x00A0)
    )
    # Seeded on purpose: a differential over two implementations has to be
    # reproducible when it fails, and nothing here is cryptographic.
    rng = random.Random(20260827)
    for _ in range(3000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 300)))
        assert _current(text) == _reference(text), repr(text[:80])


def test_the_oracle_can_actually_disagree():
    """The control.

    Every assertion above is satisfied by two functions that are the same
    function. Give the reference a set the table does not match and require the
    comparison to fail, so a future refactor that accidentally aliases the two
    implementations does not read as agreement.
    """
    rigged = str.maketrans(dict.fromkeys("abc", " "))
    text = "abc def"
    assert text.translate(rigged) != _reference(text)
