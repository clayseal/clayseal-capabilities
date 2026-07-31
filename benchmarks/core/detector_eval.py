"""Trajectory-level evaluation of the behavioral detector.

The engine ladder scores per-action authorization. This module scores the
*behavioral* layer: fit the goal-conditioned detector on benign trajectories,
then measure how many attack trajectories it contains versus how often it wrongly
blocks a held-out benign trajectory. Because the decision comes through the
conformal layer, the benign block rate is bounded by ``alpha`` by construction,
so the headline is containment at a chosen, guaranteed false-alarm budget.

Each ``BenchmarkTask`` becomes two trajectories under one sealed goal: a benign
one (its benign events) and an attack one (benign events followed by the injected
attack events). Training and calibration see only benign trajectories, matching
the one-class threat model.
"""
from __future__ import annotations

import random

from dataclasses import dataclass

from agentauth.capabilities.monitor import (
    Action,
    ContextItem,
    Trajectory,
    TrajectoryDetector,
    TrustLevel,
)
from agentauth.capabilities.scoping.goal import GoalSpec

from benchmarks.core.events import BenchmarkTask, EventLabel


def _goal_for(task: BenchmarkTask) -> GoalSpec:
    mandate = task.mandate or {}
    resources = list(mandate.get("allowed_resources", [])) or sorted(
        {c.get("resource", "") for c in task.capabilities if c.get("resource")}
    )
    verbs = sorted(mandate.get("allowed_actions", []) or {e.action for e in task.events})
    # Goal-type bucket drives the detector's per-goal calibration granularity.
    # Loaders set meta["goal_kind"] (e.g. "tau2:airline", "bfcl:multi_turn_base");
    # fall back to the suite, then a generic bucket.
    kind = task.meta.get("goal_kind") or task.meta.get("suite") or "task"
    return GoalSpec(
        query_id=task.task_id,
        summary=task.summary,
        allow_resources=resources,
        structured_intent={"kind": kind, "verbs": verbs},
    )


def task_to_trajectories(task: BenchmarkTask) -> tuple[Trajectory, Trajectory]:
    """Return ``(benign_trajectory, attack_trajectory)`` for a task."""
    goal = _goal_for(task)
    benign_actions: list[Action] = []
    attack_actions: list[Action] = []
    context: list[ContextItem] = []
    step = 0
    for event in task.events:
        act = Action(
            step=step, tool=event.tool_name, resource=event.resource,
            verb=event.action, args=dict(event.args),
            derived_from=("injection",) if event.label is EventLabel.ATTACK else (),
        )
        if event.label is EventLabel.BENIGN:
            benign_actions.append(act)
        else:
            attack_actions.append(act)
        step += 1
    context.append(ContextItem("injection", TrustLevel.UNTRUSTED, introduced_at_step=0))
    benign = Trajectory(goal=goal, actions=benign_actions, context=context)
    attack = Trajectory(goal=goal, actions=benign_actions + attack_actions, context=context)
    return benign, attack


@dataclass
class DetectorEvalResult:
    scorer: str
    alpha: float
    n_train: int
    n_test: int
    attack_trajectories: int
    contained: int
    benign_blocked: int

    @property
    def containment_rate(self) -> float:
        return self.contained / self.attack_trajectories if self.attack_trajectories else 0.0

    @property
    def false_block_rate(self) -> float:
        return self.benign_blocked / self.n_test if self.n_test else 0.0

    def summary(self) -> dict:
        return {
            "scorer": self.scorer,
            "alpha": self.alpha,
            "n_train": self.n_train,
            "n_test": self.n_test,
            "containment_rate": round(self.containment_rate, 4),
            "false_block_rate": round(self.false_block_rate, 4),
            "attack_trajectories": self.attack_trajectories,
            "contained": self.contained,
        }


def run_detector_benchmark(
    tasks: list[BenchmarkTask],
    *,
    detector: TrajectoryDetector | None = None,
    train_frac: float = 0.6,
    seed: int = 0,
) -> DetectorEvalResult:
    # Split at the TASK level, shuffled, so a task's benign context can never be
    # in training while its attack is scored at test time. The detector fits on
    # train-split benign only; both false-block and containment are measured on
    # the held-out test split. This keeps the model blind to the eval setup and
    # its expectations (no positional split, no train-task leakage).
    order = list(tasks)
    random.Random(seed).shuffle(order)
    split = max(1, int(len(order) * train_frac))
    train_tasks, test_tasks = order[:split], order[split:]

    train_benign = [b for b, _ in map(task_to_trajectories, train_tasks) if b.actions]
    test_benign, test_attack = [], []
    for task in test_tasks:
        b, a = task_to_trajectories(task)
        if b.actions:
            test_benign.append(b)
        if len(a.actions) > len(b.actions):
            test_attack.append(a)

    det = detector or TrajectoryDetector()
    det.fit(train_benign)

    benign_blocked = sum(det.assess(t).blocked for t in test_benign)
    contained = sum(det.assess(t).blocked for t in test_attack)
    return DetectorEvalResult(
        scorer=det.scorer.name, alpha=det.alpha,
        n_train=len(train_benign), n_test=len(test_benign),
        attack_trajectories=len(test_attack), contained=contained,
        benign_blocked=benign_blocked,
    )
