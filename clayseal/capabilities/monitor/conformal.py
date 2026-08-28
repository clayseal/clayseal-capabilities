"""Conformal calibration, the distribution-free false-alarm guarantee.

A raw surprise score is not a decision. Thresholding it by hand trades one
magic number for another and gives no guarantee about how often benign steps are
flagged. Conformal calibration fixes this: given surprise scores from a held-out
set of *benign* steps (the calibration set), a new score's conformal p-value is

    p = (1 + #{cal_i >= score}) / (n + 1)

Flagging when ``p <= alpha`` guarantees, under exchangeability of benign scores,
that at most an ``alpha`` fraction of benign steps are flagged in expectation.
That is the property a security control needs: the false-block rate is a dial
with a proof behind it, not an artifact of a tuned threshold. The higher the
surprise, the smaller the p-value, so miscalibrated scorers cost containment,
never the false-alarm guarantee.

``MondrianConformal`` calibrates per goal bucket. Class-conditional (Mondrian)
calibration keeps validity within each bucket, so an over-represented task type
cannot mask elevated false alarms on a rare one.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field


@dataclass
class ConformalCalibrator:
    """Single-pool conformal p-values from benign calibration scores."""

    _sorted: list[float] = field(default_factory=list)

    def fit(self, benign_scores: list[float]) -> ConformalCalibrator:
        self._sorted = sorted(benign_scores)
        return self

    @property
    def n(self) -> int:
        return len(self._sorted)

    def p_value(self, score: float) -> float:
        """Conformal p-value: fraction of calibration scores >= ``score``."""
        if not self._sorted:
            return 1.0  # no evidence -> never flag (fail open on the FP side)
        # #{cal >= score} via the first index whose value >= score.
        idx = bisect.bisect_left(self._sorted, score)
        ge = len(self._sorted) - idx
        return (1 + ge) / (self.n + 1)

    def flag(self, score: float, *, alpha: float) -> bool:
        return self.p_value(score) <= alpha


@dataclass
class MondrianConformal:
    """Per-bucket (class-conditional) conformal calibration.

    Falls back to a pooled calibrator when a bucket has too few calibration
    points to be valid on its own, so a brand-new goal type still gets a
    defensible p-value instead of a degenerate one.
    """

    min_per_bucket: int = 20
    _buckets: dict[str, ConformalCalibrator] = field(default_factory=dict)
    _pooled: ConformalCalibrator = field(default_factory=ConformalCalibrator)

    def fit(self, scored: list[tuple[str, float]]) -> MondrianConformal:
        by_bucket: dict[str, list[float]] = {}
        for bucket, score in scored:
            by_bucket.setdefault(bucket, []).append(score)
        self._buckets = {
            bucket: ConformalCalibrator().fit(scores)
            for bucket, scores in by_bucket.items()
        }
        self._pooled = ConformalCalibrator().fit([s for _, s in scored])
        return self

    def _calibrator(self, bucket: str) -> ConformalCalibrator:
        cal = self._buckets.get(bucket)
        if cal is None or cal.n < self.min_per_bucket:
            return self._pooled
        return cal

    def p_value(self, bucket: str, score: float) -> float:
        return self._calibrator(bucket).p_value(score)

    def flag(self, bucket: str, score: float, *, alpha: float) -> bool:
        return self.p_value(bucket, score) <= alpha
