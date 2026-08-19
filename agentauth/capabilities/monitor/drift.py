"""CUSUM drift detection — statistical process control for slow subversion.

Borrowed from manufacturing quality control. A Shewhart chart (our max-surprise
statistic) flags a single point outside limits, but misses a process whose mean
has *drifted*: many observations each only slightly high. That is precisely the
memo's coding-agent case — "a harmless-looking refactor in one commit and weakens
authorization logic in the next" — where every step is marginally suspicious and
no single one trips a threshold.

CUSUM accumulates the signed deviation of each step's surprise from the benign
mean, resetting at zero, and fires when the running sum crosses a limit. It is
the optimal detector of a sustained small shift, so it catches gradual drift a
point check never sees. The CUSUM statistic is calibrated per goal bucket by
conformal, like every other tier, so its false-alarm rate is bounded by alpha.
"""
from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass, field

from agentauth.capabilities.monitor.conformal import MondrianConformal


def cusum_statistic(surprises: list[float], mu0: float, k: float) -> float:
    """Max upward CUSUM: S_t = max(0, S_{t-1} + (x_t - mu0 - k)); return max_t S_t."""
    s = 0.0
    peak = 0.0
    for x in surprises:
        s = max(0.0, s + (x - mu0 - k))
        peak = max(peak, s)
    return peak


@dataclass
class CusumDrift:
    k_factor: float = 0.5  # reference-shift slack, in benign-std units
    min_samples: int = 25
    _mu: dict[str, float] = field(default_factory=dict)
    _k: dict[str, float] = field(default_factory=dict)
    _counts: dict[str, int] = field(default_factory=dict)
    _calibrator: MondrianConformal = field(default_factory=MondrianConformal)
    _fitted: bool = False

    def fit(self, per_traj: list[tuple[str, list[float]]]) -> CusumDrift:
        by_bucket: dict[str, list[float]] = defaultdict(list)
        for bucket, surprises in per_traj:
            by_bucket[bucket].extend(surprises)
        for bucket, vals in by_bucket.items():
            self._mu[bucket] = statistics.fmean(vals) if vals else 0.0
            sigma = statistics.pstdev(vals) if len(vals) > 1 else 0.0
            self._k[bucket] = self.k_factor * (sigma or 1.0)
            self._counts[bucket] = sum(1 for b, _ in per_traj if b == bucket)
        stats = [
            (bucket, cusum_statistic(surprises, self._mu.get(bucket, 0.0),
                                     self._k.get(bucket, 0.0)))
            for bucket, surprises in per_traj
        ]
        self._calibrator.fit(stats)
        self._fitted = True
        return self

    def statistic(self, bucket: str, surprises: list[float]) -> float:
        return cusum_statistic(surprises, self._mu.get(bucket, 0.0), self._k.get(bucket, 0.0))

    def p_value(self, bucket: str, surprises: list[float]) -> float:
        if not self._fitted or self._counts.get(bucket, 0) < self.min_samples:
            return 1.0  # abstain on a bucket with too few benign paths
        return self._calibrator.p_value(bucket, self.statistic(bucket, surprises))
