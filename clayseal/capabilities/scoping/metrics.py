"""DP-40: Success metrics and baselines for dynamic scoping.

Defines the metric schema and a collector that tracks key indicators
across a session (or evaluation run):

User-friction metrics:
- prompts_per_goal: step-up prompts shown to the user per goal
- false_block_rate: actions blocked that should have been allowed

Containment metrics:
- prevented_violations: protected-zone reads/writes/egress denied
- prevented_scans: scanning scorer triggers

Productivity metrics:
- time_to_first_edit_ms: time from goal start to first write action
- actions_before_first_block: actions executed before first block

Performance metrics:
- broker_overhead_p50_ms: median broker pre-tool overhead
- broker_overhead_p95_ms: 95th percentile
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScopingMetrics:
    """Accumulated metrics for one goal / session (DP-40).

    Usage::

        metrics = ScopingMetrics()
        # After each tool call:
        metrics.record_action(blocked=False, step_up=False, overhead_ms=12.3)
        # After session:
        summary = metrics.summary()
    """

    goal_id: str = ""
    total_actions: int = 0
    blocked_actions: int = 0
    step_up_prompts: int = 0
    false_blocks: int = 0
    # Actions refused because the grant had stopped authorizing. Enforced
    # nowhere until an audit found a mandate 400 days expired still allowed.
    prevented_expired_grants: int = 0
    # Actions refused because the acting principal's own chain did not authorize
    # them, even though the action was inside the session's mandate.
    prevented_delegation_overreach: int = 0
    prevented_protected_reads: int = 0
    prevented_protected_writes: int = 0
    prevented_egress: int = 0
    prevented_secret_content: int = 0
    scan_triggers: int = 0
    drift_triggers: int = 0
    novelty_triggers: int = 0
    first_edit_action: int | None = None
    first_block_action: int | None = None
    _overhead_samples: list[float] = field(default_factory=list)

    def record_action(
        self,
        *,
        blocked: bool = False,
        step_up: bool = False,
        is_write: bool = False,
        overhead_ms: float = 0.0,
    ) -> None:
        self.total_actions += 1
        if overhead_ms > 0:
            self._overhead_samples.append(overhead_ms)

        if blocked:
            self.blocked_actions += 1
            if self.first_block_action is None:
                self.first_block_action = self.total_actions

        if step_up:
            self.step_up_prompts += 1

        if is_write and self.first_edit_action is None:
            self.first_edit_action = self.total_actions

    def record_false_block(self) -> None:
        self.false_blocks += 1

    def record_prevented(
        self,
        *,
        protected_read: bool = False,
        protected_write: bool = False,
        egress: bool = False,
        expired: bool = False,
        delegation: bool = False,
        secret_content: bool = False,
    ) -> None:
        if expired:
            self.prevented_expired_grants += 1
        if delegation:
            self.prevented_delegation_overreach += 1
        if protected_read:
            self.prevented_protected_reads += 1
        if protected_write:
            self.prevented_protected_writes += 1
        if egress:
            self.prevented_egress += 1
        if secret_content:
            # Counted separately from egress on purpose. The destination was
            # allowed; what was refused is the payload. Folding it into the
            # egress counter would make an operator read a content refusal as a
            # destination refusal and look in the wrong place.
            self.prevented_secret_content += 1

    def record_monitor_trigger(
        self,
        *,
        scan: bool = False,
        drift: bool = False,
        novelty: bool = False,
    ) -> None:
        if scan:
            self.scan_triggers += 1
        if drift:
            self.drift_triggers += 1
        if novelty:
            self.novelty_triggers += 1

    @property
    def prompts_per_goal(self) -> float:
        return float(self.step_up_prompts)

    @property
    def false_block_rate(self) -> float:
        if self.blocked_actions == 0:
            return 0.0
        return self.false_blocks / self.blocked_actions

    @property
    def broker_overhead_p50_ms(self) -> float:
        if not self._overhead_samples:
            return 0.0
        return statistics.median(self._overhead_samples)

    @property
    def broker_overhead_p95_ms(self) -> float:
        if not self._overhead_samples:
            return 0.0
        sorted_samples = sorted(self._overhead_samples)
        idx = int(len(sorted_samples) * 0.95)
        return sorted_samples[min(idx, len(sorted_samples) - 1)]

    def summary(self) -> dict[str, Any]:
        return {
            "goal_id": self.goal_id,
            "total_actions": self.total_actions,
            "blocked_actions": self.blocked_actions,
            "step_up_prompts": self.step_up_prompts,
            "prompts_per_goal": self.prompts_per_goal,
            "false_blocks": self.false_blocks,
            "false_block_rate": round(self.false_block_rate, 4),
            "prevented": {
                "protected_reads": self.prevented_protected_reads,
                "protected_writes": self.prevented_protected_writes,
                "egress": self.prevented_egress,
                "total": (
                    self.prevented_protected_reads
                    + self.prevented_protected_writes
                    + self.prevented_egress
                ),
            },
            "monitor_triggers": {
                "scan": self.scan_triggers,
                "drift": self.drift_triggers,
                "novelty": self.novelty_triggers,
            },
            "first_edit_action": self.first_edit_action,
            "first_block_action": self.first_block_action,
            "actions_before_first_block": (
                (self.first_block_action - 1) if self.first_block_action else self.total_actions
            ),
            "broker_overhead_p50_ms": round(self.broker_overhead_p50_ms, 2),
            "broker_overhead_p95_ms": round(self.broker_overhead_p95_ms, 2),
        }


# Baselines (v1 targets, advisory)
BASELINE_TARGETS = {
    "prompts_per_goal_max": 1.0,
    "false_block_rate_max": 0.05,
    "broker_overhead_p95_max_ms": 50.0,
    "prevented_violations_min": 0,
}
