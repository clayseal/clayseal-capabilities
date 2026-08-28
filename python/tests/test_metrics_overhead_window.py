"""The module that measures overhead must not be the one that leaks.

`_overhead_samples` was an unbounded `list`, appended once per authorization and
sorted in full on every read of `broker_overhead_p95_ms` — which `summary()`
reads next to the median, so one summary sorted the whole history twice. Two
defects in one field: memory that grows for as long as the object lives, and a
read that gets slower the longer it has been collecting.

A `deque(maxlen=...)` bounds it, in the same shape `DecisionLog` bounds its
records, and exact counters carry what the window drops.

**Scope, stated honestly.** This is ~8 bytes of the ~1,180 per call that a
session grows by; the trajectory dominates and is not addressed here. What this
fixes outright is the case where one `ScopingMetrics` outlives a session — the
field is constructible by a caller and nothing stops it being shared across many
— where it grew for the lifetime of the process.
"""
from __future__ import annotations

import time

from clayseal.capabilities.scoping.metrics import OVERHEAD_SAMPLE_WINDOW, ScopingMetrics


def _record(metrics: ScopingMetrics, n: int, overhead_ms: float = 0.05) -> None:
    for _ in range(n):
        metrics.record_action(overhead_ms=overhead_ms)


def test_the_window_is_bounded_however_long_the_session_runs():
    m = ScopingMetrics(goal_id="g")
    _record(m, 100_000)
    assert len(m._overhead_samples) == OVERHEAD_SAMPLE_WINDOW
    assert m._overhead_samples.maxlen == OVERHEAD_SAMPLE_WINDOW


def test_the_exact_counters_survive_eviction():
    """The window forgets; these must not. `count` and `sum` are what make the
    mean exact over the session rather than over the tail."""
    m = ScopingMetrics(goal_id="g")
    _record(m, 100_000, overhead_ms=0.10)
    assert m.overhead_count == 100_000
    assert m.overhead_evicted == 100_000 - OVERHEAD_SAMPLE_WINDOW
    # A running sum of 100,000 floats accumulates error; the relative error here
    # is ~2e-13, far below the two decimal places `summary()` rounds to.
    assert abs(m.broker_overhead_mean_ms - 0.10) < 1e-9


def test_a_spike_outside_the_window_is_still_reported():
    """The reason exact counters exist at all.

    A p95 over a window cannot see a stall that has scrolled out of it. `max` is
    the number that actually matters against `broker_overhead_p95_max_ms`, and it
    was not reported at all before this change.
    """
    m = ScopingMetrics(goal_id="g")
    m.record_action(overhead_ms=999.0)
    _record(m, OVERHEAD_SAMPLE_WINDOW + 10)
    assert m.broker_overhead_p95_ms < 1.0, "the spike should have left the window"
    assert m.overhead_max_ms == 999.0, "but the exact maximum must keep it"
    assert m.summary()["broker_overhead_max_ms"] == 999.0


def test_reading_the_summary_does_not_get_slower_as_the_session_grows():
    """The O(n log n)-per-read half of the defect.

    Compared as a ratio rather than against a wall-clock threshold, so this does
    not turn into a flaky timing test on a shared CI runner.
    """
    small = ScopingMetrics(goal_id="small")
    _record(small, OVERHEAD_SAMPLE_WINDOW)
    big = ScopingMetrics(goal_id="big")
    _record(big, OVERHEAD_SAMPLE_WINDOW * 50)

    def cost(m: ScopingMetrics) -> float:
        start = time.perf_counter()
        for _ in range(20):
            m.summary()
        return time.perf_counter() - start

    cost(small), cost(big)          # warm
    assert cost(big) < cost(small) * 4, (
        "summary() still scales with session length; the window is not bounding it")


def test_the_summary_says_the_percentiles_are_over_a_window():
    """A percentile over the last N decisions read as one over the session would
    be a quietly wrong number. The payload has to carry its own caveat."""
    m = ScopingMetrics(goal_id="g")
    _record(m, OVERHEAD_SAMPLE_WINDOW * 3)
    s = m.summary()
    assert s["overhead_samples"] == OVERHEAD_SAMPLE_WINDOW
    assert s["overhead_evicted"] == OVERHEAD_SAMPLE_WINDOW * 2
    assert "broker_overhead_mean_ms" in s
    assert "broker_overhead_max_ms" in s


def test_a_short_session_is_exact_and_unchanged():
    """The control on the other side.

    Below the window nothing is evicted, so the percentiles must be exactly what
    the old unbounded implementation produced. If this drifts, the change was not
    a bound, it was a behaviour change.
    """
    m = ScopingMetrics(goal_id="g")
    for value in (0.01, 0.02, 0.03, 0.04, 0.05):
        m.record_action(overhead_ms=value)
    assert m.overhead_evicted == 0
    assert m.broker_overhead_p50_ms == 0.03
    assert m.broker_overhead_p95_ms == 0.05
    assert m.overhead_max_ms == 0.05
    assert abs(m.broker_overhead_mean_ms - 0.03) < 1e-9


def test_zero_overhead_is_not_recorded_as_a_sample():
    """Unchanged behaviour, asserted so the counters cannot drift from the
    window: `record_action` only samples when overhead is positive."""
    m = ScopingMetrics(goal_id="g")
    for _ in range(10):
        m.record_action(overhead_ms=0.0)
    assert m.total_actions == 10
    assert m.overhead_count == 0
    assert len(m._overhead_samples) == 0
    assert m.broker_overhead_p50_ms == 0.0
