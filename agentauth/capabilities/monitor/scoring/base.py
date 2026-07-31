"""Sequence-scorer contract.

A scorer assigns each action a *surprise* under a goal-conditioned model of
benign trajectories: higher means less consistent with how this goal is usually
pursued. Surprise is an uncalibrated real number; turning it into a decision
with a controlled false-alarm rate is the conformal layer's job, so scorers stay
free to use any scale (negative log-likelihood, distance, energy) as long as
larger is more anomalous.

Keeping this a narrow protocol is what lets the deterministic n-gram baseline and
the learned transformer be swapped without touching calibration, the detector, or
the benchmark.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from agentauth.capabilities.monitor.action import Trajectory


@dataclass(frozen=True)
class ScoredStep:
    step: int
    surprise: float


@runtime_checkable
class SequenceScorer(Protocol):
    name: str

    def surprise(self, traj: Trajectory) -> list[ScoredStep]:
        """Per-action surprise for every action in ``traj`` (larger = odder)."""
        ...
