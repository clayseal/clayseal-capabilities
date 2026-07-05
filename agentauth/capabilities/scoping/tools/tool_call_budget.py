"""Session-level (tool, target) call budget -- the mechanism that actually
defeats decomposition/structuring exploits (a task split across multiple
individually-valid calls to evade a business-rule boundary). A commit token
proves one call's payload integrity; this tracks cumulative session state
that per-call binding structurally cannot express.

Default strictness is tiered by tool risk (plan Q2), not a single global
constant: high-risk tools (irreversible/financial writes -- reuse whatever
set a caller already treats as commit-required) default to
``max_calls_per_target=1``; everything else defaults higher, since same
-target repeats of a lower-risk tool (e.g. lock/unlock a device) are
legitimate and shouldn't be blocked by default.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCallBudgetConfig:
    high_risk_tools: frozenset[str] = field(default_factory=frozenset)
    high_risk_max_calls_per_target: int = 1
    default_max_calls_per_target: int = 3
    scope: str = "tool_target"  # "tool_target" | "target"
    tightened: bool = False
    # Tools where a same-session call may *supersede* (void-and-replace) a
    # prior one via a matching idempotency key, rather than count as a new
    # call. Only for reversible tools: money already irrevocably sent cannot
    # be replaced, so a "correction" there genuinely IS a second effect and
    # must still hit the gate. Safe against a lying agent by construction:
    # same-key reuse is defined as replace, so it can only ever *reduce* a
    # total (see the correction-vs-cap-eviction analysis in the backlog).
    supersession_eligible: frozenset[str] = field(default_factory=frozenset)

    def limit_for(self, tool_name: str) -> int:
        if tool_name in self.high_risk_tools:
            return self.high_risk_max_calls_per_target
        return self.default_max_calls_per_target


@dataclass
class ToolCallBudget:
    config: ToolCallBudgetConfig = field(default_factory=ToolCallBudgetConfig)
    calls: dict[tuple[str, str], int] = field(default_factory=dict)
    # (tool, target) -> set of idempotency keys already seen (each = one slot)
    seen_keys: dict[tuple[str, str], set[str]] = field(default_factory=dict)

    def _key(self, tool_name: str, target_entity: str) -> tuple[str, str]:
        if self.config.scope == "target":
            return ("*", target_entity)
        return (tool_name, target_entity)

    def _is_supersede(
        self, tool_name: str, key: tuple[str, str], idempotency_key: str | None
    ) -> bool:
        return (
            idempotency_key is not None
            and tool_name in self.config.supersession_eligible
            and idempotency_key in self.seen_keys.get(key, set())
        )

    def would_allow(
        self,
        tool_name: str,
        target_entity: str | None,
        *,
        idempotency_key: str | None = None,
    ) -> tuple[bool, str]:
        """Non-mutating check -- safe to call from a monitoring/dry-run pass."""
        if target_entity is None:
            return True, "ok_no_target"
        if self.config.tightened:
            return False, "tool_call_budget_disabled_tightened"
        key = self._key(tool_name, target_entity)
        if self._is_supersede(tool_name, key, idempotency_key):
            return True, "supersede_replace"
        limit = self.config.limit_for(tool_name)
        if self.calls.get(key, 0) >= limit:
            return False, "target_call_budget_exhausted"
        return True, "ok"

    def commit(
        self,
        tool_name: str,
        target_entity: str | None,
        *,
        idempotency_key: str | None = None,
    ) -> None:
        """Consume budget. Call only after a call is confirmed non-blocked --
        never from a monitoring-only pass, or budgets exhaust on phantom calls."""
        if target_entity is None:
            return
        key = self._key(tool_name, target_entity)
        if self._is_supersede(tool_name, key, idempotency_key):
            return  # replace: reuses the prior slot, no new consumption
        self.calls[key] = self.calls.get(key, 0) + 1
        if idempotency_key is not None and tool_name in self.config.supersession_eligible:
            self.seen_keys.setdefault(key, set()).add(idempotency_key)

    def try_consume(
        self,
        tool_name: str,
        target_entity: str | None,
        *,
        idempotency_key: str | None = None,
    ) -> tuple[bool, str]:
        """Convenience check-and-commit in one call, for callers (e.g. direct
        unit tests) that don't need the check/commit split."""
        allowed, reason = self.would_allow(
            tool_name, target_entity, idempotency_key=idempotency_key
        )
        if allowed:
            self.commit(tool_name, target_entity, idempotency_key=idempotency_key)
        return allowed, reason

    def enter_tightened_mode(self) -> None:
        self.config.tightened = True

    def exit_tightened_mode(self) -> None:
        self.config.tightened = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "calls": {f"{tool}:{target}": count for (tool, target), count in self.calls.items()},
            "scope": self.config.scope,
            "tightened": self.config.tightened,
        }
