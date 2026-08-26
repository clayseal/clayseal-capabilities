"""The longitudinal question: did behaviour move toward the edge of the grant?

The distinction these tests exist to hold is the whole reason the module is not
another drift dashboard. A workload that changes completely while staying well
inside its authority has not become more dangerous. A workload whose action
distribution is IDENTICAL but which now runs at 88% of a ceiling it used to
touch at 12% has, and no test on the behaviour distribution can tell them apart
because on that evidence they are the same in the wrong direction.
"""
from __future__ import annotations

import pytest

from agentauth.capabilities.behavior_baseline import (
    APPROACHING,
    INSIDE,
    UNCHANGED,
    UNCOVERED,
    VOID,
    BehaviorProfile,
    SessionSummary,
    action_token,
    compare,
    fisher_exact_greater,
    holm,
    profile_from,
    rule_of_three,
    summarize_session,
)


def sess(tokens, headroom=None, step_up=0, deny=0):
    n = sum(tokens.values())
    return SessionSummary(
        tokens=tokens,
        outcomes={"allow": n - step_up - deny, "step_up": step_up, "deny": deny},
        headroom=headroom or {})


def profile(n, tokens, headroom=None, digest="sha256:aaa", **kw):
    return profile_from([sess(tokens, headroom, **kw) for _ in range(n)],
                        policy_digest=digest)


BASE = {"tokens": {"read|get_invoice|data": 3, "transfer|pay|net": 1},
        "headroom": {"payments": 0.12}}


# ------------------------------------------------------------- statistics ---
def test_fisher_matches_a_known_table():
    assert fisher_exact_greater(8, 2, 1, 9) == pytest.approx(0.00274, abs=1e-5)


def test_fisher_on_an_identical_table_does_not_fire():
    assert fisher_exact_greater(5, 5, 5, 5) > 0.5


def test_an_absent_category_is_not_a_category_with_rate_zero():
    """With 50 approval sessions the true rate could still be 6%."""
    assert rule_of_three(50) == pytest.approx(0.06)
    assert rule_of_three(0) == 1.0


def test_holm_is_applied_across_channels():
    decided = holm({"a": 0.001, "b": 0.04, "c": 0.9}, alpha=0.05)
    assert decided["a"] and not decided["c"]


# ---------------------------------------------------------- the verdicts ----
def test_a_workload_that_changed_but_stayed_cool_is_not_an_alarm():
    """The case a distributional monitor calls an incident and should not."""
    base = profile(40, **BASE)
    later = profile(40, tokens={"read|get_invoice|data": 20},
                    headroom={"payments": 0.10})
    assert compare(base, later).verdict != APPROACHING


def test_the_same_distribution_running_hot_is_an_alarm():
    """Identical action counts. Only the distance to the ceiling moved."""
    base = profile(40, **BASE)
    later = profile(40, tokens=BASE["tokens"], headroom={"payments": 0.88})
    report = compare(base, later)
    assert report.verdict == APPROACHING
    assert [c.name for c in report.fired()] == ["headroom"]


def test_a_changed_grant_voids_the_baseline_rather_than_ageing_it():
    base = profile(40, **BASE)
    later = profile(40, digest="sha256:bbb", **BASE)
    assert compare(base, later).verdict == VOID


def test_an_unchanged_workload_says_so():
    base = profile(40, **BASE)
    assert compare(base, profile(40, **BASE)).verdict == UNCHANGED


def test_new_action_shapes_alone_read_as_inside_the_grant():
    base = profile(40, **BASE)
    later = profile_from(
        [sess({"read|get_invoice|data": 3, "transfer|pay|net": 1},
              {"payments": 0.12}) for _ in range(39)]
        + [sess({"read|list_vendors|data": 1}, {"payments": 0.12})],
        policy_digest="sha256:aaa")
    assert compare(base, later).verdict == INSIDE


def test_a_baseline_that_stopped_describing_the_workload_says_so():
    """Half the approved shapes retired and nothing new appeared.

    This is a weaker statement than an alarm and a stronger one than silence:
    the other channels are still testing, but against a baseline that now
    describes less of the workload than it did, so a null from them means less.
    """
    base = profile(40, **BASE)
    later = profile(40, tokens={"read|get_invoice|data": 20},
                    headroom={"payments": 0.10})
    assert compare(base, later).verdict == UNCOVERED


def test_a_brand_new_action_shape_in_every_session_is_an_alarm():
    """Authority creep: the agent is doing something it was never approved for.

    Distinct from the case above, where the workload shrank onto shapes that
    were already approved. Here it reaches for one that was not.
    """
    base = profile(40, **BASE)
    later = profile(40, tokens={"write|new_tool|net": 4},
                    headroom={"payments": 0.10})
    report = compare(base, later)
    assert report.verdict == APPROACHING
    assert "novel-authority" in {c.name for c in report.fired()}


def test_rising_friction_is_a_risk_channel():
    base = profile(40, tokens=BASE["tokens"], headroom=BASE["headroom"])
    later = profile(40, tokens=BASE["tokens"], headroom=BASE["headroom"],
                    step_up=3)
    report = compare(base, later)
    assert report.verdict == APPROACHING
    assert "friction" in {c.name for c in report.fired()}


# ------------------------------------------------------------- discipline ---
def test_a_blind_channel_is_reported_as_blind_rather_than_as_passing():
    """No budget state supplied is not the same as no headroom change."""
    base = profile_from([sess(BASE["tokens"]) for _ in range(20)])
    later = profile_from([sess(BASE["tokens"]) for _ in range(20)])
    headroom = [c for c in compare(base, later).channels if c.name == "headroom"]
    assert headroom and not headroom[0].available


def test_a_null_result_carries_what_it_could_not_have_resolved():
    report = compare(profile(12, **BASE), profile(12, **BASE))
    assert "not evidence of stability" in report.resolvable
    assert "25.0%" in report.resolvable


def test_the_profile_holds_counts_and_never_arguments():
    """A profile is committable and auditable because there is nothing in it."""
    from agentauth.capabilities.decision_log import DecisionRecord

    record = DecisionRecord(
        seq=0, receipt_id="r", created_at="t", query_id="q", tool="pay_vendor",
        resource="/finance/ap/inv-001.json", action_verb="transfer",
        arguments_hash="sha256:secret", outcome="allow", layer="-",
        reasons=(), anomaly_score=None, prev_hash="")
    summary = summarize_session([record])
    body = str(summary.tokens) + str(summary.outcomes)
    assert "inv-001" not in body and "sha256:secret" not in body
    assert summary.tokens == {action_token("transfer", "pay_vendor", "finance"): 1}


def test_a_profile_round_trips_through_its_own_serialization():
    base = profile(20, **BASE)
    again = BehaviorProfile.from_dict(base.to_dict())
    assert again.digest() == base.digest()
    assert again.sessions == 20


# ------------------------------------------------ the test has to return ----
def test_the_exact_test_is_bounded_and_still_returns():
    """A certification pass that hangs on real data is not a certification pass.

    Measured before this bound existed: 40 events took microseconds, 8,000 took
    499ms, and 200,000, which is an ordinary month of production traffic, did
    not return at all.
    """
    import time

    start = time.perf_counter()
    p = fisher_exact_greater(500_000, 500_000, 400_000, 600_000)
    assert 0.0 <= p <= 1.0
    assert time.perf_counter() - start < 1.0


def test_the_approximation_agrees_with_the_exact_test_where_both_run():
    """A p-value computed two ways is two claims unless they agree.

    Pins the crossover: a future edit that moves `EXACT_MAX_TOTAL` without
    checking the two against each other fails here.
    """
    from agentauth.capabilities.behavior_baseline import _normal_greater

    for a, b, c, d in [(30, 70, 20, 80), (60, 140, 40, 160),
                       (250, 750, 200, 800), (400, 600, 350, 650)]:
        assert abs(fisher_exact_greater(a, b, c, d)
                   - _normal_greater(a, b, c, d)) < 1e-3


def test_the_crossover_is_named_rather_than_silent():
    from agentauth.capabilities.behavior_baseline import (
        EXACT_MAX_TERMS,
        EXACT_MAX_TOTAL,
    )

    assert EXACT_MAX_TOTAL > 0 and EXACT_MAX_TERMS > 0


# ------------------------------------------- the statistics, as properties ---
@pytest.mark.parametrize("a,b,c,d", [
    (0, 0, 0, 0), (1, 0, 0, 0), (0, 1, 0, 1), (0, 0, 5, 5),
    (10, 0, 0, 10), (0, 10, 10, 0), (1, 1, 1, 1), (7, 3, 3, 7),
    (10**6, 1, 1, 10**6), (1, 10**6, 10**6, 1),
])
def test_the_test_is_total_and_in_range(a, b, c, d):
    """Never raises, always a probability, on any table including degenerate."""
    p = fisher_exact_greater(a, b, c, d)
    assert 0.0 <= p <= 1.0


def test_more_hits_never_raises_the_p_value():
    """Monotone in the direction it claims to test."""
    previous = 1.1
    for a in range(0, 41):
        p = fisher_exact_greater(a, 40 - a, 20, 20)
        assert p <= previous + 1e-12, (a, p, previous)
        previous = p


def test_an_identical_table_is_not_evidence_of_a_rise():
    for n in (10, 100, 1000, 10_000):
        assert fisher_exact_greater(n, n, n, n) > 0.4


def test_a_randomized_sweep_stays_total_bounded_and_ordered():
    """The systematic version of the three cases above.

    The defects in this module were found by typing candidates at a REPL, and
    the lesson recorded elsewhere in this session is that a probe built with the
    same blind spot as the code reports clean. This sweeps rather than picks.
    """
    import random
    import time

    rng = random.Random(11)  # noqa: S311 - a sweep, not a secret
    start = time.perf_counter()
    for _ in range(600):
        scale = rng.choice([1, 10, 1000, 100_000])
        a, b, c, d = (rng.randrange(0, scale + 1) for _ in range(4))
        p = fisher_exact_greater(a, b, c, d)
        assert 0.0 <= p <= 1.0
        if a + b and c + d:
            # A strictly higher current rate cannot be LESS surprising.
            assert fisher_exact_greater(a + 1, max(b - 1, 0), c, d) <= p + 1e-9
    # Generous, and the number is measured rather than hoped for: the exact
    # branch runs a sum over up to EXACT_MAX_TERMS terms with `math.comb` on
    # four-digit integers, which is tens of milliseconds a call. That is fine
    # for a certification pass called a handful of times and is why the branch
    # exists at all rather than the exact test running everywhere.
    assert time.perf_counter() - start < 20.0
