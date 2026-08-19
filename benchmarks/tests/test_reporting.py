"""How a number is allowed to be published."""
from __future__ import annotations

import pytest

from benchmarks.core.reporting import (
    ModelIdentity, PreRegistration, format_rate, one_sided_upper, publishable,
)


# --------------------------------------------------------------------------- #
# Never a bare zero.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("n,expected_max", [
    (18, 0.19), (20, 0.17), (100, 0.04), (949, 0.005),
])
def test_a_zero_carries_an_upper_bound(n, expected_max):
    """`frontier.md` says it of itself: a 0% ASR at n=18 has an upper bound near
    18%, and that "applies to every 0% ASR in this repository"."""
    bound = one_sided_upper(0, n)
    assert 0 < bound <= expected_max


def test_the_bound_shrinks_with_n():
    bounds = [one_sided_upper(0, n) for n in (18, 20, 100, 500, 949)]
    assert bounds == sorted(bounds, reverse=True)


def test_a_zero_never_renders_as_a_bare_percentage():
    """The formatting rule, not just the arithmetic."""
    rendered = format_rate(0, 20)
    assert "0.0%" not in rendered
    assert "upper bound" in rendered


def test_a_nonzero_renders_as_a_point_estimate():
    assert "2.5%" in format_rate(3, 120)


def test_an_empty_denominator_is_not_a_rate():
    assert "n/a" in format_rate(0, 0)


def test_exact_rather_than_normal_approximate():
    """The normal approximation is worst exactly where this is used: small n and
    a rate near zero, where it returns a bound of 0."""
    assert one_sided_upper(0, 18) > 0.15
    assert one_sided_upper(1, 100) < one_sided_upper(5, 100)


# --------------------------------------------------------------------------- #
# Model identity.
# --------------------------------------------------------------------------- #
def test_a_deployment_alias_is_flagged_and_relabelled():
    """Live: `clayseal-aoai`'s deployment is named `gpt-4o-mini-2024-07-18` and
    serves `gpt-5-mini-2025-08-07`. A model-strength trend is the central claim
    of `improvements.md`, and one mislabelled cell inverts it."""
    m = ModelIdentity(requested="gpt-4o-mini-2024-07-18",
                      reported="gpt-5-mini-2025-08-07", provider="azure")
    assert m.mismatched
    assert m.label().startswith("gpt-5-mini-2025-08-07")
    assert "gpt-4o-mini" in m.label()      # the alias stays visible


def test_a_matching_model_is_not_flagged():
    m = ModelIdentity(requested="gpt-4o-mini-2024-07-18",
                      reported="gpt-4o-mini-2024-07-18")
    assert not m.mismatched
    assert m.label() == "gpt-4o-mini-2024-07-18"


def test_an_unverified_model_says_so():
    assert "unverified" in ModelIdentity(requested="x", reported="").label()


# --------------------------------------------------------------------------- #
# Pre-registration.
# --------------------------------------------------------------------------- #
def test_the_hash_is_stable_and_design_sensitive():
    def make(**kw):
        base = dict(hypothesis="h", primary_metric="m", cells=["a"],
                    n_per_cell=100, seeds=[0, 1], created_at="fixed")
        base.update(kw)
        return PreRegistration(**base)

    assert make().hash() == make().hash()
    assert make().hash() != make(n_per_cell=50).hash()
    assert make().hash() != make(cells=["a", "b"]).hash()


def test_the_stopping_rule_is_recorded_by_default():
    """A cell re-run after a bad result is indistinguishable afterwards from one
    that was not, unless the rule was written down first."""
    rule = PreRegistration(hypothesis="h", primary_metric="m", cells=[],
                           n_per_cell=1, seeds=[]).stopping_rule
    assert "no re-run" in rule and "fixed n" in rule


# --------------------------------------------------------------------------- #
# The gate.
# --------------------------------------------------------------------------- #
def test_the_repos_own_headline_shape_is_rejected():
    """n=20, one seed, bare zero, unverified model: the exact shape of the
    head-to-head cell the plan calls not publishable."""
    ok, problems = publishable({"n": 20, "successes": 0, "seeds": [0], "model": {}})
    assert not ok
    assert len(problems) >= 3


def test_a_properly_reported_cell_passes():
    ok, problems = publishable({
        "n": 120, "successes": 0, "upper_bound": 0.031,
        "seeds": [0, 1, 2, 3, 4], "prereg_hash": "prereg:abc",
        "model": {"reported": "gpt-5-mini-2025-08-07"}})
    assert ok, problems


def test_a_missing_prereg_marks_the_cell_exploratory():
    _, problems = publishable({
        "n": 120, "successes": 3, "seeds": [0, 1, 2, 3, 4],
        "model": {"reported": "m"}})
    assert any("exploratory" in p for p in problems)


def test_seed_count_is_enforced():
    _, problems = publishable({
        "n": 120, "successes": 3, "seeds": [0, 1], "prereg_hash": "p",
        "model": {"reported": "m"}})
    assert any("seeds" in p for p in problems)
