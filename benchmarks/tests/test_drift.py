"""Tests for the slow-drift and anchor-displacement benchmark.

The claim being measured is about the defense, not the agent: a monitor that
learns normal from traffic it has already permitted can be retrained by a
patient adversary rather than evaded. These tests pin the properties that make
that claim mean something, because the instrument is easy to build in a way that
produces the desired answer by construction.
"""
from __future__ import annotations

from benchmarks.drift import Monitor, run


def test_rolling_baseline_follows_the_attacker():
    result = run(actions=10000, ramp=0.0008, baseline=10.0, target=14.0,
                 window=500, sigmas=3.0, seed=0)
    rolling = result["monitors"]["rolling"]
    assert rolling["displacement_sigmas"] > 3.0, (
        "the rolling baseline should track the drift; if it does not, the "
        "benchmark is not exercising the feedback loop it exists to show"
    )
    assert rolling["terminal_alarm_rate"] < 0.05


def test_anchored_baseline_does_not_move():
    """Zero displacement is the defining property, not an empirical finding."""
    result = run(actions=10000, ramp=0.0008, baseline=10.0, target=14.0,
                 window=500, sigmas=3.0, seed=0)
    anchored = result["monitors"]["anchored"]
    assert anchored["displacement_sigmas"] == 0.0
    assert anchored["terminal_alarm_rate"] > 0.5


def test_both_monitors_see_identical_data():
    """The comparison is only fair if the two regimes judge the same stream.

    Guards the obvious way to fake this result: give the anchored monitor a
    different or harsher sample.
    """
    seen = {"rolling": [], "anchored": []}
    original = Monitor.observe

    def spy(self, value, step, terminal=False):
        seen.setdefault(self.name, []).append(value)
        return original(self, value, step, terminal)

    Monitor.observe = spy
    try:
        run(actions=500, ramp=0.008, baseline=10.0, target=14.0,
            window=100, sigmas=3.0, seed=1)
    finally:
        Monitor.observe = original
    assert seen["rolling"] == seen["anchored"]


def test_no_drift_means_no_displacement_and_no_alarms():
    """The null case. A stationary agent must not produce either signal, or the
    benchmark is measuring the ramp mechanics rather than drift."""
    result = run(actions=5000, ramp=0.0, baseline=10.0, target=10.0,
                 window=500, sigmas=3.0, seed=2)
    for name in ("rolling", "anchored"):
        m = result["monitors"][name]
        assert abs(m["displacement_sigmas"]) < 0.2
        assert m["terminal_alarm_rate"] < 0.02, (
            f"{name} alarms on a stationary agent at "
            f"{m['terminal_alarm_rate']:.1%}, which is a false-positive rate, "
            "not a detection"
        )


def test_a_sudden_jump_is_caught_by_both():
    """Drift is the attack a rolling monitor misses. It should still catch a
    step change, otherwise the comparison is unfair to it."""
    rolling = Monitor("rolling", sigmas=3.0, window=500).fit(
        [10.0 + (i % 7) * 0.1 for i in range(500)])
    assert rolling.observe(30.0, step=0) is True


def test_displacement_is_measured_in_anchor_sigmas():
    monitor = Monitor("m", window=10).fit([0.0, 1.0, 2.0, 1.0, 0.0])
    start = monitor.mu
    for i in range(200):
        monitor.observe(50.0, i)
    assert monitor.mu > start
    assert monitor.displacement > 0
