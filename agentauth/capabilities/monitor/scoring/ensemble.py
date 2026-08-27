"""Ensemble scorer: combine complementary sequence scorers.

The n-gram and transformer scorers have opposite strengths, the sharp n-gram is
sensitive to repetition and rare transitions, the transformer generalizes across
unseen tokens. Combining them recovers both. Each member's surprise is
standardized against its own benign distribution (so incomparable scales become
comparable), then combined by ``max`` (flag if *any* member finds the step very
surprising) or ``mean``.

Standardization stats are fit on benign trajectories, so the ensemble stays a
drop-in ``SequenceScorer`` behind the same conformal calibration.
"""
from __future__ import annotations

import statistics

from agentauth.capabilities.monitor.action import Trajectory
from agentauth.capabilities.monitor.scoring.base import ScoredStep, SequenceScorer


class EnsembleScorer:
    name = "ensemble"

    def __init__(self, members: list[SequenceScorer], *, combine: str = "max") -> None:
        if not members:
            raise ValueError("ensemble needs at least one member scorer")
        self.members = members
        self.combine = combine
        self._mean: list[float] = [0.0] * len(members)
        self._std: list[float] = [1.0] * len(members)

    def fit(self, benign: list[Trajectory]) -> EnsembleScorer:
        for scorer in self.members:
            member_fit = getattr(scorer, "fit", None)
            if callable(member_fit):
                member_fit(benign)
        for j, scorer in enumerate(self.members):
            vals = [s.surprise for traj in benign for s in scorer.surprise(traj)]
            if vals:
                self._mean[j] = statistics.fmean(vals)
                self._std[j] = statistics.pstdev(vals) or 1e-9
        return self

    def surprise(self, traj: Trajectory) -> list[ScoredStep]:
        per_member = [scorer.surprise(traj) for scorer in self.members]
        n = len(traj.actions)
        out: list[ScoredStep] = []
        for i in range(n):
            zs = [
                (per_member[j][i].surprise - self._mean[j]) / self._std[j]
                for j in range(len(self.members))
                if i < len(per_member[j])
            ]
            if not zs:
                out.append(ScoredStep(traj.actions[i].step, 0.0))
                continue
            combined = max(zs) if self.combine == "max" else statistics.fmean(zs)
            out.append(ScoredStep(traj.actions[i].step, combined))
        return out
