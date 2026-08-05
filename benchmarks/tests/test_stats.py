"""Tests for the uncertainty machinery.

These matter more than most tests here: every published rate will be quoted
with an interval produced by this module, so a wrong interval is a wrong claim
made in public. The properties checked are the ones that would let us overstate
a result.
"""
from __future__ import annotations

import pytest

from benchmarks.core.stats import (
    Interval,
    SeedSpread,
    cluster_bootstrap_ci,
    is_resolved,
    proportion_ci,
)


# --------------------------------------------------------------------------- #
# Wilson
# --------------------------------------------------------------------------- #
def test_wilson_does_not_collapse_at_zero():
    """0 of 718 must not report as certainty. This is the failure mode."""
    ci = proportion_ci(0, 718)
    assert ci.point == 0.0
    assert ci.low == 0.0
    assert 0.0 < ci.high < 0.01


def test_wilson_stays_inside_the_unit_interval():
    for successes, n in [(0, 5), (5, 5), (1, 3), (99, 100)]:
        ci = proportion_ci(successes, n)
        assert 0.0 <= ci.low <= ci.point <= ci.high <= 1.0


def test_wilson_narrows_with_n():
    small = proportion_ci(5, 10)
    large = proportion_ci(500, 1000)
    assert large.half_width < small.half_width


def test_empty_sample_is_maximally_uncertain():
    ci = proportion_ci(0, 0)
    assert (ci.low, ci.high) == (0.0, 1.0)


# --------------------------------------------------------------------------- #
# Cluster bootstrap
# --------------------------------------------------------------------------- #
def test_cluster_interval_is_wider_than_the_event_interval():
    """The whole reason for clustering.

    Twenty tasks of ten correlated events each: half the tasks fully blocked,
    half fully allowed. Event-level maths sees 200 independent trials at 50%
    and reports a tight interval. The truth is 20 observations, and the
    clustered interval must be visibly wider.
    """
    clusters = [(10, 10)] * 10 + [(0, 10)] * 10
    clustered = cluster_bootstrap_ci(clusters, resamples=2000, seed=1)
    naive = proportion_ci(100, 200)
    assert clustered.point == pytest.approx(0.5)
    assert clustered.half_width > naive.half_width * 1.5


def test_cluster_bootstrap_is_deterministic_under_seed():
    clusters = [(3, 10), (7, 10), (0, 10), (10, 10), (5, 10)]
    a = cluster_bootstrap_ci(clusters, seed=7)
    b = cluster_bootstrap_ci(clusters, seed=7)
    assert (a.low, a.high) == (b.low, b.high)


def test_unanimous_clusters_get_a_rule_of_three_bound():
    """Every cluster identical means every resample is identical, so the
    percentile interval has zero width. That must not be reported as such."""
    ci = cluster_bootstrap_ci([(0, 10)] * 30, seed=0)
    assert ci.method == "rule-of-three"
    assert ci.point == 0.0
    assert ci.high == pytest.approx(0.1)  # 3/30

    perfect = cluster_bootstrap_ci([(10, 10)] * 30, seed=0)
    assert perfect.point == 1.0
    assert perfect.low == pytest.approx(0.9)


def test_more_clusters_tighten_the_unanimous_bound():
    """A 100% result over 700 templates is stronger evidence than over 20."""
    few = cluster_bootstrap_ci([(5, 5)] * 20, seed=0)
    many = cluster_bootstrap_ci([(5, 5)] * 700, seed=0)
    assert many.low > few.low


def test_single_cluster_falls_back_to_event_level():
    """One task carries no between-cluster information, but reporting a
    zero-width interval would be worse than reporting the naive one."""
    ci = cluster_bootstrap_ci([(3, 10)], seed=0)
    assert ci.method == "wilson"
    assert ci.low < ci.point < ci.high


def test_no_clusters_is_maximally_uncertain():
    ci = cluster_bootstrap_ci([], seed=0)
    assert (ci.low, ci.high) == (0.0, 1.0)


# --------------------------------------------------------------------------- #
# Resolution
# --------------------------------------------------------------------------- #
def test_overlapping_intervals_are_not_resolved():
    """The audit's 55.6% / 11.1% / 12.5% case: with n=8 nothing is resolved."""
    a = proportion_ci(5, 9)
    b = proportion_ci(1, 9)
    assert a.overlaps(b)
    assert not is_resolved(a, b)


def test_separated_intervals_are_resolved():
    a = proportion_ci(717, 718)
    b = proportion_ci(0, 718)
    assert is_resolved(a, b)


# --------------------------------------------------------------------------- #
# Seed spread
# --------------------------------------------------------------------------- #
def test_seed_spread_reports_the_range_not_just_the_mean():
    spread = SeedSpread((0.556, 0.111, 0.125), label="asr")
    s = spread.summary()
    assert s["min"] == 0.111 and s["max"] == 0.556
    assert spread.stdev > 0.2
    assert spread.interval().high > spread.interval().low


def test_single_seed_has_no_spread_and_says_so():
    spread = SeedSpread((0.4,))
    assert spread.stdev == 0.0
    ci = spread.interval()
    assert ci.low == ci.high == pytest.approx(0.4)


def test_interval_render_is_readable():
    assert Interval(0.999, 0.996, 1.0, 718).render() == "99.9% [99.6%, 100.0%]"
