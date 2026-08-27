"""Trajectory-level evaluation of the behavioral detector.

The engine ladder scores per-action authorization. This module scores the
*behavioral* layer: fit the goal-conditioned detector on benign trajectories,
then measure how many attack trajectories it contains versus how often it wrongly
blocks a held-out benign trajectory. Each blocking tier is a per-bucket
split-conformal test bounded at ``alpha``; the tiers block on disjoint shapes so
the empirical union false-alarm rate stays near ``alpha`` (worst case k*alpha),
and it tracks ``alpha`` as a conformal control must. The headline is containment
at a measured false-alarm rate, not a per-construction guarantee.

Each ``BenchmarkTask`` becomes two trajectories under one sealed goal: a benign
one (its benign events) and an attack one (benign events followed by the injected
attack events, or, for ``parallel_twins``, the attack transcript alone).
Parallel-twin attacks are assessed with ``reference=benign`` so the twin
corridor / intent two-signal / surface gate can fire. Training and calibration
see only benign trajectories, matching the one-class threat model.
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
    # Prefer an explicit resource list; else materialize from scope.allowed_paths
    # (SLEIGHT stores the benign twin's surface there, including net: egress).
    resources = list(mandate.get("allowed_resources", []))
    if not resources:
        scope = mandate.get("scope") or {}
        paths = scope.get("allowed_paths") or []
        if paths:
            resources = [str(p) for p in paths]
    if not resources:
        resources = sorted(
            {c.get("resource", "") for c in task.capabilities if c.get("resource")}
        )
    # Corpus-agnostic backfill: destinations mentioned in benign event bodies
    # belong on the sealed goal even when the loader only recorded file paths.
    from agentauth.capabilities.monitor.sealed_plan import extract_destinations
    for event in task.events:
        if event.label is not EventLabel.BENIGN:
            continue
        if event.path and str(event.path).startswith("net:"):
            resources.append(str(event.path))
        for key in ("command", "content", "new_string", "body", "file_text"):
            val = (event.args or {}).get(key)
            if isinstance(val, str) and val:
                resources.extend(extract_destinations(val))
    # Dedup, preserve order.
    seen: set[str] = set()
    resources = [r for r in resources if r and not (r in seen or seen.add(r))]
    # Task summary from the mandate when the loader put one there.
    task_block = mandate.get("task") if isinstance(mandate.get("task"), dict) else {}
    summary = (
        (task_block or {}).get("summary")
        or task.summary
        or ""
    )
    # The goal is SEALED from the legitimate task: its expected verbs come from the
    # user's own (benign) steps or an explicit mandate, never from injected events.
    # Deriving verbs from attack events would silently widen the envelope to admit
    # exactly the verb an injection introduces (e.g. an unexpected ``send``), which
    # both hurts containment and misstates what the user authorized. The label is
    # used only to define the sealed goal up front, never consulted at assess time.
    benign_events = [e for e in task.events if e.label is EventLabel.BENIGN]
    benign_verbs = {e.action for e in benign_events}
    verbs = sorted(mandate.get("allowed_actions", []) or benign_verbs)
    benign_tools = sorted({e.tool_name for e in benign_events})
    # Goal-type bucket drives the detector's per-goal calibration granularity.
    # Loaders set meta["goal_kind"] (e.g. "tau2:airline", "bfcl:multi_turn_base");
    # SLEIGHT uses category so twin corridors do not collapse to one bucket.
    kind = task.meta.get("goal_kind")
    if not kind and task.meta.get("category"):
        kind = f"sleight:{task.meta['category']}"
    kind = kind or task.meta.get("suite") or "task"
    return GoalSpec(
        query_id=task.task_id,
        summary=str(summary),
        allow_resources=resources,
        structured_intent={
            "kind": kind,
            "verbs": verbs,
            "tools": benign_tools,
        },
    )


# Read-style verbs that ingest content the agent did not author. Crossing one of
# these means later actions may be justified by untrusted external content.
_READ_VERBS = frozenset(
    {"read", "get", "list", "search", "fetch", "view", "query", "retrieve", "load", "scan"}
)


def _parallel_twins(task: BenchmarkTask) -> bool:
    """SLEIGHT-style paired transcripts: attack is a parallel twin, not a suffix."""
    return task.meta.get("trajectory_mode") == "parallel_twins"


def task_to_trajectories(task: BenchmarkTask) -> tuple[Trajectory, Trajectory]:
    """Return ``(benign_trajectory, attack_trajectory)`` for a task.

    Provenance is DATA-FLOW derived, never label-derived. An action is marked
    driven-by-untrusted-context once the trajectory has already ingested content
    from an external read earlier in the stream; the rule reads only the verb
    order, so benign and attack actions are treated identically and the
    ground-truth ATTACK label is never consulted to taint an action. The detector
    must therefore separate benign from attack by BEHAVIOUR, an untrusted-driven
    action that leaves the sealed goal, not by reading which events were injected.

    Injection-style tasks (AgentDojo, fixtures): attack = benign prefix + injected
    steps. Parallel-twin tasks (SLEIGHT): attack is the attack transcript alone,
    under the goal sealed from the benign twin. Prepending the benign twin here
    invents a session that never happened; scoring attack-only tasks with an
    empty verb set is the other cheat (empty goal ⇒ ~60% fake containment).
    """
    goal = _goal_for(task)
    # Empty sealed verbs on an attack-only stream is the SLEIGHT artifact: every
    # action looks out-of-goal. Refuse that shape when the task claims a twin.
    if _parallel_twins(task) and not (goal.structured_intent or {}).get("verbs"):
        raise ValueError(
            f"parallel-twin task {task.task_id!r} sealed an empty verb set; "
            "goal verbs must come from the benign twin"
        )
    context = [
        ContextItem("external-content", TrustLevel.UNTRUSTED, introduced_at_step=0)
    ]
    if _parallel_twins(task):
        benign_actions: list[Action] = []
        attack_actions: list[Action] = []
        ingested_b = ingested_a = False
        for event in task.events:
            if event.label is EventLabel.BENIGN:
                act = Action(
                    step=len(benign_actions), tool=event.tool_name,
                    resource=event.resource, verb=event.action,
                    args=dict(event.args),
                    derived_from=("external-content",) if ingested_b else (),
                    meta={"path": event.path} if event.path else {},
                )
                if event.action.lower() in _READ_VERBS:
                    ingested_b = True
                benign_actions.append(act)
            else:
                # UNLABELED cover work stays in the attack twin stream.
                act = Action(
                    step=len(attack_actions), tool=event.tool_name,
                    resource=event.resource, verb=event.action,
                    args=dict(event.args),
                    derived_from=("external-content",) if ingested_a else (),
                    meta={"path": event.path} if event.path else {},
                )
                if event.action.lower() in _READ_VERBS:
                    ingested_a = True
                attack_actions.append(act)
        return (
            Trajectory(goal=goal, actions=benign_actions, context=context),
            Trajectory(goal=goal, actions=attack_actions, context=context),
        )

    benign_actions = []
    attack_actions = []
    step = 0
    ingested = False
    for event in task.events:
        act = Action(
            step=step, tool=event.tool_name, resource=event.resource,
            verb=event.action, args=dict(event.args),
            derived_from=("external-content",) if ingested else (),
            meta={"path": event.path} if event.path else {},
        )
        if event.action.lower() in _READ_VERBS:
            ingested = True
        if event.label is EventLabel.BENIGN:
            benign_actions.append(act)
        elif event.label is not EventLabel.UNLABELED:
            attack_actions.append(act)
        step += 1
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
    # (benign, attack_or_None, use_twin_reference)
    test_cases: list[tuple] = []
    for task in test_tasks:
        b, a = task_to_trajectories(task)
        if not b.actions:
            continue
        if _parallel_twins(task):
            # Score the attack twin against its sealed benign reference.
            test_cases.append((b, a if a.actions else None, True))
        elif len(a.actions) > len(b.actions):
            test_cases.append((b, a, False))
        else:
            test_cases.append((b, None, False))

    det = detector or TrajectoryDetector()
    det.fit(train_benign)

    # Benign FB: population tiers only (twin-local corridor is clean by
    # construction on its own reference and must not zero-out the FB column).
    benign_blocked = sum(det.assess(b).blocked for b, _, _ in test_cases)
    contained = 0
    n_attack = 0
    for b, a, twin in test_cases:
        if a is None:
            continue
        n_attack += 1
        report = det.assess(a, reference=b) if twin else det.assess(a)
        contained += int(report.blocked)
    return DetectorEvalResult(
        scorer=det.scorer.name, alpha=det.alpha,
        n_train=len(train_benign), n_test=len(test_cases),
        attack_trajectories=n_attack, contained=contained,
        benign_blocked=benign_blocked,
    )
