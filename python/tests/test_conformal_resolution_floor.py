"""A conformal tier gated below its own resolution floor can never fire.

A conformal p-value is `(1 + #{cal >= score}) / (n + 1)`, so its smallest
possible value is `1 / (n + 1)`. Gate a tier at an alpha below that and it is
arithmetically incapable of blocking, whatever it observes. It fails silently:
it still runs, still returns a p-value, and still reports success.

Measured on the shipped detector the floor is 0.0909 against an alpha of 0.05,
which is why swapping its scorer for `target`, or for one emitting uniform
noise, changed nothing. Both the `scorer` and `path` tiers are in that state.
See docs/INTEGRATION.md.
"""

from __future__ import annotations

from clayseal.capabilities.monitor.action import Action, Trajectory
from clayseal.capabilities.monitor.conformal import ConformalCalibrator
from clayseal.capabilities.monitor.detector import TrajectoryDetector
from clayseal.capabilities.scoping.goal import GoalSpec


def _cal(n: int) -> ConformalCalibrator:
    return ConformalCalibrator().fit([float(i) for i in range(n)])


def test_the_floor_is_one_over_n_plus_one() -> None:
    assert _cal(10).resolution_floor == 1 / 11
    assert _cal(99).resolution_floor == 1 / 100


def test_an_alpha_below_the_floor_is_unreachable() -> None:
    assert not _cal(10).can_reach(0.05)
    assert _cal(10).can_reach(0.10)


def test_it_says_how_much_calibration_is_missing() -> None:
    cal = _cal(10)
    assert cal.calibration_needed(0.05) == 9      # n must reach 19
    assert _cal(19).can_reach(0.05)
    assert _cal(19).calibration_needed(0.05) == 0


def test_no_calibration_means_no_flag_not_a_free_flag() -> None:
    """Control: an unfitted calibrator must fail toward silence, not blocking."""
    empty = ConformalCalibrator()
    assert empty.p_value(1e9) == 1.0
    assert empty.resolution_floor == 1.0
    assert not empty.can_reach(0.05)


def _traj(n: int, tool: str = "read") -> Trajectory:
    return Trajectory(goal=GoalSpec(query_id="q", summary="read the files"), actions=[
        Action(step=i, tool=tool, resource=f"file:{i}", verb="read", args={})
        for i in range(n)])


def test_a_thinly_calibrated_detector_names_its_inert_tiers() -> None:
    det = TrajectoryDetector()
    det.fit([_traj(4) for _ in range(10)])
    assert "scorer" in det.inert_tiers(_traj(4)), (
        "a tier that cannot reach alpha must say so, or a report where it looked "
        "and found nothing is indistinguishable from one where it could not look"
    )


def test_a_well_calibrated_detector_does_not_cry_wolf() -> None:
    """Control: this must not report every tier inert regardless of input.

    Without it the assertion above would pass on a function that returned every
    tier name unconditionally.

    60 rather than 19 is the empirical threshold, and the gap is the finding.
    `fit` is split-conformal, so the scorer trains on one slice and the
    calibrator sees the other, and Mondrian then partitions what is left per
    goal bucket. The arithmetic floor needs 19 calibration points; reaching it
    through both splits takes between 40 and 60 benign trajectories per bucket.
    The benchmark harness fits on 25 to 30, which is why every published
    detector number is a structural-tier result.
    """
    det = TrajectoryDetector()
    det.fit([_traj(4) for _ in range(60)])
    assert "scorer" not in det.inert_tiers(_traj(4))


def test_the_threshold_sits_between_forty_and_sixty() -> None:
    """Pin the number an operator needs, so a change to `fit` shows up here."""
    def inert_at(n: int) -> tuple[str, ...]:
        det = TrajectoryDetector()
        det.fit([_traj(4) for _ in range(n)])
        return det.inert_tiers(_traj(4))

    assert "scorer" in inert_at(40)
    assert "scorer" not in inert_at(60)


def test_an_unfitted_detector_reports_nothing_rather_than_everything() -> None:
    assert TrajectoryDetector().inert_tiers(_traj(4)) == ()
