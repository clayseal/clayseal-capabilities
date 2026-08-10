"""The property the block cover claims: assembly must not depend on arrival order.

It was claimed and not held. The cover scanned greedily, so a write consumed for
a coincidental one-character match was gone when the segment that genuinely
needed it came up, and whether that happened depended on the order the fragments
arrived in. Sending them in order gave greedy an order it could follow, which is
why sequential tests passed and concurrent ones did not.

These tests fail against greedy and pass against the bounded search.
"""
from __future__ import annotations

import random
from concurrent.futures import ThreadPoolExecutor

import pytest

from agentauth.capabilities.confidentiality import (
    FlowTracker, SensitivityPolicy, _assemblable, _compact_fold,
    _longest_prefix_in)

POLICY = SensitivityPolicy(sensitive=("db:customers",),
                           declassified_sinks=("mail:board",))
KEY = "AKIA0123456789ABCDEFQZ"
FILLER = "the quarterly reconciliation summary for the northern region " * 10


def _fragments(count: int) -> list[str]:
    size = max(1, len(KEY) // count)
    return [KEY[i:i + size] for i in range(0, len(KEY), size)]


def _tracker() -> FlowTracker:
    tracker = FlowTracker()
    tracker.observe("read", "db:customers", KEY, policy=POLICY,
                    structured_fields={"key": KEY})
    return tracker


def _escaped(fragments: list[str], *, concurrent: bool) -> str:
    """What an attacker reassembles from the writes that were ALLOWED out."""
    tracker = _tracker()

    def send(fragment: str) -> bool:
        return tracker.check(tool="w", verb="write", resource="log:agent",
                             args={"body": f"{FILLER} {fragment}"},
                             policy=POLICY).allowed

    if concurrent:
        with ThreadPoolExecutor(max_workers=len(fragments)) as pool:
            allowed = list(pool.map(send, fragments))
    else:
        allowed = [send(f) for f in fragments]
    return "".join(f for f, ok in zip(fragments, allowed) if ok)


@pytest.mark.parametrize("count", [2, 11, 22])
def test_the_value_does_not_escape_in_any_arrival_order(count):
    """Every permutation the scheduler might pick has to hold, not just the one
    that happens to match the order of the value."""
    fragments = _fragments(count)
    rng = random.Random(0)
    for _ in range(4):
        shuffled = fragments[:]
        rng.shuffle(shuffled)
        assert KEY not in _escaped(shuffled, concurrent=False)


@pytest.mark.parametrize("count", [2, 11, 22])
def test_the_value_does_not_escape_under_concurrency(count):
    """Parallel arrival is a shuffle for free, and it is how the gap showed up.

    Eleven fragments issued in parallel reassembled in 2 of 12 trials after the
    lost-update race was closed, because the race was only half of it.
    """
    fragments = _fragments(count)
    for _ in range(3):
        assert KEY not in _escaped(fragments, concurrent=True)


def test_the_cover_is_a_property_of_the_pieces_not_their_order():
    """Stated directly against the algorithm, without the tracker in the way."""
    target = _compact_fold(KEY)
    # Compacted and folded, because that is the form the tracker accumulates.
    pieces = [_compact_fold(FILLER + f) for f in _fragments(22)]
    rng = random.Random(1)
    for _ in range(30):
        shuffled = pieces[:]
        rng.shuffle(shuffled)
        assert _assemblable(target, shuffled)


def test_a_value_that_was_never_sent_is_not_assembled():
    """The other direction, or the test above is satisfied by always saying yes."""
    absent = _compact_fold("ZZZZ9876543210ZZZZWXYV")
    assert not _assemblable(absent, [_compact_fold(FILLER + f)
                                     for f in _fragments(22)])


def test_one_write_cannot_cover_two_segments():
    """The distinctness constraint is what stops a benign repeated word from
    assembling a value that repeats it."""
    assert not _assemblable("northwindnorthwind", ["shipped via northwind today"])
    assert _assemblable("northwindnorthwind",
                        ["shipped via northwind today", "northwind again"])


def test_longest_prefix_binary_search_matches_the_linear_definition():
    """The search is monotone, and this pins that the fast form agrees."""
    rng = random.Random(2)
    for _ in range(2000):
        block = "".join(rng.choice("abcdef") for _ in range(rng.randint(1, 60)))
        needle = "".join(rng.choice("abcdef") for _ in range(rng.randint(1, 12)))
        expected = next((n for n in range(min(len(needle), len(block)), 0, -1)
                         if needle[:n] in block), 0)
        assert _longest_prefix_in(needle, block) == expected


def test_the_search_is_bounded_so_an_attacker_cannot_price_us_out():
    """The attacker chooses the block set, so the budget has to be a ceiling."""
    import time

    blocks = [_compact_fold(FILLER + f"tail{i}") for i in range(512)]
    start = time.perf_counter()
    assert not _assemblable(_compact_fold(KEY), blocks)
    assert time.perf_counter() - start < 1.0
