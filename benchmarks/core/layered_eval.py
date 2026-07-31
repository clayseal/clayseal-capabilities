"""Defense-in-depth evaluation: enforcement floor + behavioral detector.

The per-action floor contains attacks that leave the authorized surface. The
residual — injections that stay entirely within the authorized tool, args, and
scope — is exactly what the behavioral detector is meant to catch. This module
measures the two together:

  floor containment      attacks blocked by the enforcement engine
  residual               attacks the floor lets through (in-scope injections)
  detector recovery      residual attacks the trajectory detector then blocks
  combined containment   floor + detector
  detector false-block   benign trajectories the detector wrongly blocks (cost)

The detector is fit only on benign trajectories (one-class), and the floor and
detector are evaluated on the same held-out tasks, so the combined number is an
honest end-to-end containment for the layered system.
"""
from __future__ import annotations

import random

from dataclasses import dataclass

from agentauth.capabilities.monitor import TrajectoryDetector
from benchmarks.core.detector_eval import task_to_trajectories
from benchmarks.core.engines import DecisionEngine, build_engines
from benchmarks.core.events import BenchmarkTask, EventLabel


@dataclass
class LayeredResult:
    floor_engine: str
    scorer: str
    alpha: float
    n_attack_tasks: int
    floor_contained: int
    residual: int
    detector_recovered: int
    benign_eval: int
    detector_false_blocks: int

    @property
    def floor_rate(self) -> float:
        return self.floor_contained / self.n_attack_tasks if self.n_attack_tasks else 0.0

    @property
    def combined_rate(self) -> float:
        return (self.floor_contained + self.detector_recovered) / self.n_attack_tasks if self.n_attack_tasks else 0.0

    @property
    def residual_recovery_rate(self) -> float:
        return self.detector_recovered / self.residual if self.residual else 0.0

    @property
    def detector_false_block_rate(self) -> float:
        return self.detector_false_blocks / self.benign_eval if self.benign_eval else 0.0

    def summary(self) -> dict:
        return {
            "floor_engine": self.floor_engine,
            "scorer": self.scorer,
            "alpha": self.alpha,
            "n_attack_tasks": self.n_attack_tasks,
            "floor_containment": round(self.floor_rate, 4),
            "residual": self.residual,
            "detector_recovered": self.detector_recovered,
            "residual_recovery": round(self.residual_recovery_rate, 4),
            "combined_containment": round(self.combined_rate, 4),
            "detector_false_block": round(self.detector_false_block_rate, 4),
        }


def _floor_blocks_task(engine: DecisionEngine, task: BenchmarkTask) -> bool:
    """True if the engine blocks any attack event of the task."""
    for event in task.events:
        if event.label is EventLabel.ATTACK and not engine.decide(task, event).allowed:
            return True
    return False


def run_layered(
    tasks: list[BenchmarkTask],
    *,
    engine_name: str = "task-scope+binding+budget",
    detector: TrajectoryDetector | None = None,
    train_frac: float = 0.5,
    seed: int = 0,
) -> LayeredResult:
    engine = build_engines([engine_name])[0]
    detector = detector or TrajectoryDetector()

    # Shuffled task-level split: eval attacks come only from held-out tasks, so
    # the detector never trained on their benign context. A positional split
    # could put a whole goal bucket in train or test and bias the result.
    order = list(tasks)
    random.Random(seed).shuffle(order)
    split = max(1, int(len(order) * train_frac))
    train_tasks, eval_tasks = order[:split], order[split:]

    # Fit the detector on benign trajectories from the train split only.
    train_benign = [b for b, _ in map(task_to_trajectories, train_tasks) if b.actions]
    detector.fit(train_benign)

    attack_tasks = [t for t in eval_tasks if any(e.label is EventLabel.ATTACK for e in t.events)]
    floor_contained = residual = recovered = 0
    for task in attack_tasks:
        if _floor_blocks_task(engine, task):
            floor_contained += 1
            continue
        residual += 1
        _, attack_traj = task_to_trajectories(task)
        if detector.assess(attack_traj).blocked:
            recovered += 1

    benign_eval = [b for b, _ in map(task_to_trajectories, eval_tasks) if b.actions]
    false_blocks = sum(detector.assess(b).blocked for b in benign_eval)

    return LayeredResult(
        floor_engine=engine_name, scorer=detector.scorer.name, alpha=detector.alpha,
        n_attack_tasks=len(attack_tasks), floor_contained=floor_contained,
        residual=residual, detector_recovered=recovered,
        benign_eval=len(benign_eval), detector_false_blocks=false_blocks,
    )
