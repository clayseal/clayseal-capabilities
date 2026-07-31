"""Replay tasks through engines and score containment vs friction.

Populates the existing ``agentauth.capabilities.scoping.metrics.ScopingMetrics``
schema (false_block_rate, prevented_violations, broker overhead percentiles) so
the benchmark speaks the metric vocabulary the library already defines, and adds
the containment axis the security datasets require.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from agentauth.capabilities.scoping.metrics import ScopingMetrics

from benchmarks.core.engines import DecisionEngine
from benchmarks.core.events import BenchmarkTask, EventLabel

_EGRESS_ACTIONS = {"send", "post", "email", "egress", "transfer", "share", "publish"}
_WRITE_ACTIONS = {"write", "create", "update", "delete", "transfer"}


@dataclass
class EngineResult:
    engine: str
    n_benign: int = 0
    n_attack: int = 0
    benign_allowed: int = 0
    benign_blocked: int = 0
    attack_allowed: int = 0  # containment failures
    attack_blocked: int = 0  # prevented violations
    overhead_ms: list[float] = field(default_factory=list)
    metrics: ScopingMetrics = field(default_factory=ScopingMetrics)

    @property
    def attack_prevention_rate(self) -> float:
        return self.attack_blocked / self.n_attack if self.n_attack else 0.0

    @property
    def false_block_rate(self) -> float:
        return self.benign_blocked / self.n_benign if self.n_benign else 0.0

    @property
    def benign_utility_rate(self) -> float:
        return self.benign_allowed / self.n_benign if self.n_benign else 0.0

    @property
    def overhead_p50_ms(self) -> float:
        return _percentile(self.overhead_ms, 0.50)

    @property
    def overhead_p95_ms(self) -> float:
        return _percentile(self.overhead_ms, 0.95)

    def summary(self) -> dict:
        return {
            "engine": self.engine,
            "n_benign": self.n_benign,
            "n_attack": self.n_attack,
            "attack_prevention_rate": round(self.attack_prevention_rate, 4),
            "false_block_rate": round(self.false_block_rate, 4),
            "benign_utility_rate": round(self.benign_utility_rate, 4),
            "attack_allowed": self.attack_allowed,
            "benign_blocked": self.benign_blocked,
            "overhead_p50_ms": round(self.overhead_p50_ms, 4),
            "overhead_p95_ms": round(self.overhead_p95_ms, 4),
        }


def _percentile(samples: list[float], q: float) -> float:
    if not samples:
        return 0.0
    ordered = sorted(samples)
    idx = min(int(len(ordered) * q), len(ordered) - 1)
    return ordered[idx]


def run_benchmark(
    tasks: list[BenchmarkTask],
    engines: list[DecisionEngine],
) -> dict[str, EngineResult]:
    """Replay every event of every task through every engine."""
    results = {engine.name: EngineResult(engine=engine.name) for engine in engines}
    for engine in engines:
        result = results[engine.name]
        for task in tasks:
            result.metrics.goal_id = task.task_id
            for event in task.events:
                start = time.perf_counter()
                decision = engine.decide(task, event)
                overhead_ms = (time.perf_counter() - start) * 1000.0
                result.overhead_ms.append(overhead_ms)
                _record(result, task, event, decision, overhead_ms)
    return results


def _record(result: EngineResult, task, event, decision, overhead_ms: float) -> None:
    is_write = event.action in _WRITE_ACTIONS
    blocked = not decision.allowed
    result.metrics.record_action(
        blocked=blocked, is_write=is_write, overhead_ms=overhead_ms
    )
    if event.label is EventLabel.BENIGN:
        result.n_benign += 1
        if decision.allowed:
            result.benign_allowed += 1
        else:
            result.benign_blocked += 1
            result.metrics.record_false_block()
    else:  # ATTACK
        result.n_attack += 1
        if decision.allowed:
            result.attack_allowed += 1
        else:
            result.attack_blocked += 1
            result.metrics.record_prevented(
                egress=event.action in _EGRESS_ACTIONS,
                protected_write=is_write and event.action not in _EGRESS_ACTIONS,
                protected_read=not is_write and event.action not in _EGRESS_ACTIONS,
            )
