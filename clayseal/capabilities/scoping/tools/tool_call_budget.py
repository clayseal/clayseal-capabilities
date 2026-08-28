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

import threading
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
class ToolCallReservation:
    """Handle for a call slot reserved atomically at check-time.

    When ``allowed`` is True the caller MUST finalize with :meth:`commit` (call
    confirmed) or roll back with :meth:`release` (call blocked/failed). Both are
    idempotent; a supersede-replace reservation settles as a no-op."""

    allowed: bool
    reason: str
    _budget: ToolCallBudget | None = None
    _key: tuple[str, str] | None = None
    _tool_name: str | None = None
    _idempotency_key: str | None = None
    _supersede: bool = False
    _settled: bool = False

    def commit(self) -> None:
        if self._budget is not None:
            self._budget._commit_reservation(self)

    def release(self) -> None:
        if self._budget is not None:
            self._budget._release_reservation(self)


@dataclass
class ToolCallBudget:
    config: ToolCallBudgetConfig = field(default_factory=ToolCallBudgetConfig)
    calls: dict[tuple[str, str], int] = field(default_factory=dict)
    # (tool, target) -> set of idempotency keys already seen (each = one slot)
    seen_keys: dict[tuple[str, str], set[str]] = field(default_factory=dict)
    # (tool, target) -> slots reserved but not yet committed/released.
    reserved: dict[tuple[str, str], int] = field(default_factory=dict)
    _lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)

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
        """Non-mutating check -- safe to call from a monitoring/dry-run pass.
        Reflects (but does not consume) outstanding reservations. This is a
        *preview*; use :meth:`reserve` for the atomic gate."""
        if target_entity is None:
            return True, "ok_no_target"
        if self.config.tightened:
            return False, "tool_call_budget_disabled_tightened"
        key = self._key(tool_name, target_entity)
        if self._is_supersede(tool_name, key, idempotency_key):
            return True, "supersede_replace"
        limit = self.config.limit_for(tool_name)
        with self._lock:
            used = self.calls.get(key, 0) + self.reserved.get(key, 0)
        if used >= limit:
            return False, "target_call_budget_exhausted"
        return True, "ok"

    def reserve(
        self,
        tool_name: str,
        target_entity: str | None,
        *,
        idempotency_key: str | None = None,
    ) -> ToolCallReservation:
        """Atomic gate: check the (committed + reserved) count against the limit
        AND record the reservation under one lock. Defeats the parallel
        check/commit TOCTOU where N calls all pass ``would_allow`` then all
        ``commit``. Finalize with :meth:`ToolCallReservation.commit` (or
        ``release``)."""
        if target_entity is None:
            return ToolCallReservation(True, "ok_no_target")
        with self._lock:
            if self.config.tightened:
                return ToolCallReservation(False, "tool_call_budget_disabled_tightened")
            key = self._key(tool_name, target_entity)
            if self._is_supersede(tool_name, key, idempotency_key):
                # replace reuses the prior slot: allowed, but nothing to settle.
                return ToolCallReservation(
                    True, "supersede_replace", _budget=self, _key=key,
                    _tool_name=tool_name, _idempotency_key=idempotency_key,
                    _supersede=True,
                )
            limit = self.config.limit_for(tool_name)
            used = self.calls.get(key, 0) + self.reserved.get(key, 0)
            if used >= limit:
                return ToolCallReservation(False, "target_call_budget_exhausted")
            self.reserved[key] = self.reserved.get(key, 0) + 1
            return ToolCallReservation(
                True, "ok", _budget=self, _key=key,
                _tool_name=tool_name, _idempotency_key=idempotency_key,
            )

    def _commit_reservation(self, res: ToolCallReservation) -> None:
        with self._lock:
            if res._settled or res._key is None or res._supersede:
                res._settled = True
                return
            key = res._key
            self.reserved[key] = max(0, self.reserved.get(key, 0) - 1)
            self.calls[key] = self.calls.get(key, 0) + 1
            if (
                res._idempotency_key is not None
                and res._tool_name in self.config.supersession_eligible
            ):
                self.seen_keys.setdefault(key, set()).add(res._idempotency_key)
            res._settled = True

    def _release_reservation(self, res: ToolCallReservation) -> None:
        with self._lock:
            if res._settled or res._key is None or res._supersede:
                res._settled = True
                return
            self.reserved[res._key] = max(0, self.reserved.get(res._key, 0) - 1)
            res._settled = True

    def commit(
        self,
        tool_name: str,
        target_entity: str | None,
        *,
        idempotency_key: str | None = None,
    ) -> None:
        """Consume budget directly (legacy check-then-commit path). Call only
        after a call is confirmed non-blocked -- never from a monitoring-only
        pass, or budgets exhaust on phantom calls. Lock-guarded, but NOT atomic
        with an earlier ``would_allow`` -- prefer :meth:`reserve` for the gate."""
        if target_entity is None:
            return
        with self._lock:
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
        """Convenience atomic check-and-commit in one call, for callers (e.g.
        direct unit tests) that don't need the reserve/commit split."""
        res = self.reserve(tool_name, target_entity, idempotency_key=idempotency_key)
        if res.allowed:
            res.commit()
        return res.allowed, res.reason

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
