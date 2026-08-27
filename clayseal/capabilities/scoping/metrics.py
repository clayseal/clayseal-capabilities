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
from collections import deque
from dataclasses import dataclass, field
from typing import Any

#: How many recent overhead samples the percentiles are taken over.
#:
#: 2,048 floats is about 16 KB per session and one `sorted()` of it is well under
#: a millisecond, off the decision path. The bound matters more than the exact
#: number: before it, a gateway running for a day held one float per
#: authorization forever and re-sorted all of them on every read.
OVERHEAD_SAMPLE_WINDOW = 2048


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
    #: The recent overhead samples the percentiles are taken over.
    #:
    #: This was an unbounded `list`, appended once per authorization and sorted
    #: in full on every read of `broker_overhead_p95_ms` — which `summary()`
    #: reads alongside the median, so a summary sorted the whole session twice.
    #: In a long-lived gateway that is a leak in the module whose job is
    #: measuring cost, and an O(n log n) read that grows with the session.
    #:
    #: A `deque` with `maxlen` bounds it in the same shape `DecisionLog` uses for
    #: its records. The percentiles become "over the last
    #: `OVERHEAD_SAMPLE_WINDOW` decisions" rather than over the session, which is
    #: the honest trade and is why the exact counters below exist: a slow first
    #: minute of a ten-hour session leaves the percentiles but stays visible in
    #: `broker_overhead_max_ms` and the mean.
    _overhead_samples: deque[float] = field(
        default_factory=lambda: deque(maxlen=OVERHEAD_SAMPLE_WINDOW))
    #: Exact over the whole session, never evicted. `max` is the number that
    #: actually matters against a p95 ceiling and was not reported at all before.
    overhead_count: int = 0
    overhead_sum_ms: float = 0.0
    overhead_max_ms: float = 0.0
    #: Samples dropped from the window, so a reader can see that the percentiles
    #: are over a window without having to infer it. Same purpose as
    #: `DecisionLog.evicted`.
    overhead_evicted: int = 0

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
            if len(self._overhead_samples) == self._overhead_samples.maxlen:
                self.overhead_evicted += 1
            self._overhead_samples.append(overhead_ms)
            self.overhead_count += 1
            self.overhead_sum_ms += overhead_ms
            self.overhead_max_ms = max(self.overhead_max_ms, overhead_ms)

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

    @property
    def broker_overhead_mean_ms(self) -> float:
        """Exact over the whole session, unlike the percentiles above."""
        if not self.overhead_count:
            return 0.0
        return self.overhead_sum_ms / self.overhead_count

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
            # The percentiles are over the last `OVERHEAD_SAMPLE_WINDOW`
            # decisions. `overhead_samples` and `overhead_evicted` say so in the
            # payload, so a reader does not have to know that to read them, and
            # the mean and max are exact over the whole session.
            "broker_overhead_p50_ms": round(self.broker_overhead_p50_ms, 2),
            "broker_overhead_p95_ms": round(self.broker_overhead_p95_ms, 2),
            "broker_overhead_mean_ms": round(self.broker_overhead_mean_ms, 2),
            "broker_overhead_max_ms": round(self.overhead_max_ms, 2),
            "overhead_samples": len(self._overhead_samples),
            "overhead_evicted": self.overhead_evicted,
        }


# Baselines (v1 targets, advisory)
BASELINE_TARGETS = {
    "prompts_per_goal_max": 1.0,
    "false_block_rate_max": 0.05,
    "broker_overhead_p95_max_ms": 50.0,
    "prevented_violations_min": 0,
}
