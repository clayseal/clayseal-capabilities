"""Session-level cumulative *compute-time* budget — the wall-clock sibling of
the value ledger in ``value_budget.py`` and the call ledger in ``call_budget.py``.

``BudgetType.COMPUTE_SECONDS`` has been declarable in a mandate all along, but
``session_budgets_from_mandate`` refused it because nothing could honestly meter
it: at the tool-call level a grant of "600 compute seconds" has no observable
quantity to debit, and reinterpreting it as a call count would be the exact
category error ``mandate_budgets`` exists to prevent.

A sandboxed run makes it meterable, because the reservation *is* the kill timer.
``run_sandboxed`` reserves an estimate before launch, clamps iVisor's timeout to
whatever the grant has left, and commits the measured wall time afterwards. A
task cannot overrun its compute grant by lying, because the enforcement is the
SIGKILL, not the accounting.

WALL, NOT CPU. A VM run consumes wall time whether or not the guest is on-CPU,
and the timeout that enforces the ceiling is a wall-clock timeout. CPU seconds
are recorded alongside for observability but are deliberately not the charged
unit — ``getrusage(RUSAGE_CHILDREN)`` also counts unrelated reaped children, so
charging it would be both unfaithful to the grant and imprecise.

Concurrency mirrors the sibling ledgers: the atomic :meth:`SessionComputeBudget.
reserve` gate checks the projection AND records the reservation under one lock,
then :meth:`ComputeReservation.commit` (actual seconds) or
:meth:`ComputeReservation.release` (run never happened).
"""

from __future__ import annotations

import math
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from agentauth.capabilities.budget import (
    BudgetType,
    select_budgets,
)
from agentauth.capabilities.budget import (
    budget_attr as _budget_attr,
)


def compute_budget_config_from_mandate(
    mandate: Any,
    *,
    tracked: Mapping[str, str],
    tightened: bool = False,
) -> ComputeBudgetConfig:
    """Build a compute-seconds config from a signed mandate.

    Consumes only ``BudgetType.COMPUTE_SECONDS`` budgets. ``tracked`` maps a
    tool name to the ``budget_id`` its runs debit, so several sandboxed tools can
    share one grant and the ceiling cannot be evaded by spreading work across
    them.
    """
    budgets = _budget_attr(mandate, "budgets") or []
    ceilings: dict[str, float] = {}
    for budget in select_budgets(budgets, BudgetType.COMPUTE_SECONDS):
        budget_id = str(_budget_attr(budget, "budget_id"))
        limit = float(_budget_attr(budget, "limit"))
        remaining = float(_budget_attr(budget, "remaining"))
        ceilings[budget_id] = min(limit, remaining)
    return ComputeBudgetConfig(tracked=dict(tracked), ceilings=ceilings,
                               tightened=tightened)


def session_compute_budget_from_mandate(
    mandate: Any,
    *,
    tracked: Mapping[str, str],
    tightened: bool = False,
) -> SessionComputeBudget:
    """Create a fresh per-session compute-seconds ledger from a mandate."""
    return SessionComputeBudget(
        config=compute_budget_config_from_mandate(
            mandate, tracked=tracked, tightened=tightened))


@dataclass
class ComputeBudgetConfig:
    # tool_name -> budget_id its sandboxed runs debit
    tracked: dict[str, str] = field(default_factory=dict)
    # budget_id -> ceiling in seconds
    ceilings: dict[str, float] = field(default_factory=dict)
    tightened: bool = False

    def __post_init__(self) -> None:
        """Reject a ceiling that would silently disable this control.

        A malformed ceiling is a control-plane bug, and every way of absorbing
        one quietly is worse than refusing it. Measured before this check
        existed:

            compute  ceiling='Infinity' / 'NaN' -> float('inf') / float('nan'),
                     so a 1,000,000-second request returned allowed=True with
                     reason 'ok' and the budget was disabled outright. A NaN
                     ceiling is the worst case: every ``projected > ceiling``
                     comparison is False, so nothing is ever refused.
            value    ceiling='Infinity' / 'abc' -> InvalidOperation raised out
                     of ``reserve()``, taking the authorization call with it.
            call     ceiling='abc' -> ValueError, same shape.

        Returning ``None`` (meaning "no ceiling") would also be fail-open, so
        the only honest option is to refuse the configuration at the boundary
        where it is built. A budget that cannot be enforced must not be
        constructible.
        """
        import math

        for budget_id, raw in list(self.ceilings.items()):
            if raw is None:
                continue
            try:
                value = float(raw)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"compute ceiling for {budget_id!r} is not a number: "
                    f"{raw!r}") from exc
            if not math.isfinite(value) or value < 0:
                raise ValueError(
                    f"compute ceiling for {budget_id!r} must be finite and "
                    f"non-negative, got {raw!r}")

    def budget_for(self, tool_name: str) -> str | None:
        return self.tracked.get(tool_name)

    def ceiling_for(self, budget_id: str) -> float | None:
        raw = self.ceilings.get(budget_id)
        return None if raw is None else float(raw)


@dataclass
class ComputeReservation:
    """Handle for compute seconds reserved atomically before a run.

    ``granted_seconds`` is what the run may actually use — the smaller of the
    requested estimate and what the grant has left. Callers pass it to the
    sandbox as the timeout, which is what makes the ceiling enforceable rather
    than merely recorded.
    """

    allowed: bool
    reason: str
    granted_seconds: float = 0.0
    _budget: SessionComputeBudget | None = None
    _budget_id: str | None = None
    _reserved: float = 0.0
    _settled: bool = False

    def commit(self, actual_seconds: float | None = None) -> None:
        """Settle with the measured wall time (defaults to the full reservation).

        A run that overshoots its grant is charged what it actually used, not
        the reservation: the timeout already bounded it, and under-charging
        would let repeated overshoots accumulate silently.
        """
        if self._budget is not None:
            self._budget._commit_reservation(self, actual_seconds)

    def release(self) -> None:
        if self._budget is not None:
            self._budget._release_reservation(self)


@dataclass
class SessionComputeBudget:
    """One instance per session (the instance *is* the session's compute ledger)."""

    config: ComputeBudgetConfig = field(default_factory=ComputeBudgetConfig)
    spent: dict[str, float] = field(default_factory=dict)
    _reserved: dict[str, float] = field(default_factory=dict)
    _lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)

    def reserve(self, tool_name: str, estimate_seconds: float) -> ComputeReservation:
        """Atomic gate: check the projection against the ceiling AND record the
        reservation under one lock. When ``allowed`` is True the caller MUST
        later ``commit`` or ``release``.

        Total by contract: any input yields a decision, never an exception. A
        string estimate used to raise ``TypeError`` from the ``< 0`` comparison
        before any budget logic ran, and a non-finite one sailed through to be
        "clamped" — ``float('nan')`` was granted as ``ok_clamped``, which then
        poisons every later comparison on the ledger because NaN compares False
        against everything. Both are refused here.

        ``bool`` is excluded deliberately: ``True`` is an ``int`` in Python, so
        an estimate of ``True`` would otherwise book one second and report ``ok``.
        """
        if isinstance(estimate_seconds, bool) or not isinstance(
            estimate_seconds, (int, float)
        ):
            return ComputeReservation(False, "compute_budget_unusable_estimate")
        if not math.isfinite(estimate_seconds):
            return ComputeReservation(False, "compute_budget_unusable_estimate")
        if estimate_seconds < 0:
            raise ValueError("estimate_seconds must not be negative")
        budget_id = self.config.budget_for(tool_name)
        if budget_id is None:
            return ComputeReservation(True, "ok_untracked",
                                      granted_seconds=estimate_seconds)
        if self.config.tightened:
            return ComputeReservation(False, "compute_budget_disabled_tightened")
        ceiling = self.config.ceiling_for(budget_id)
        with self._lock:
            if ceiling is None:
                self._reserved[budget_id] = (
                    self._reserved.get(budget_id, 0.0) + estimate_seconds)
                return ComputeReservation(
                    True, "ok_no_ceiling", granted_seconds=estimate_seconds,
                    _budget=self, _budget_id=budget_id,
                    _reserved=estimate_seconds)
            left = ceiling - (self.spent.get(budget_id, 0.0)
                              + self._reserved.get(budget_id, 0.0))
            if left <= 0:
                return ComputeReservation(False, "compute_budget_exhausted")
            # Clamp rather than refuse: a run that fits in the remaining grant
            # is authorized for exactly that long, and the timeout enforces it.
            granted = min(estimate_seconds, left)
            self._reserved[budget_id] = (
                self._reserved.get(budget_id, 0.0) + granted)
            return ComputeReservation(
                True, "ok" if granted == estimate_seconds else "ok_clamped",
                granted_seconds=granted, _budget=self, _budget_id=budget_id,
                _reserved=granted)

    def _commit_reservation(self, res: ComputeReservation,
                            actual_seconds: float | None) -> None:
        with self._lock:
            if res._settled or res._budget_id is None:
                res._settled = True
                return
            bid = res._budget_id
            charged = res._reserved if actual_seconds is None else max(
                0.0, float(actual_seconds))
            self._reserved[bid] = self._reserved.get(bid, 0.0) - res._reserved
            self.spent[bid] = self.spent.get(bid, 0.0) + charged
            res._settled = True

    def _release_reservation(self, res: ComputeReservation) -> None:
        with self._lock:
            if res._settled or res._budget_id is None:
                res._settled = True
                return
            bid = res._budget_id
            self._reserved[bid] = self._reserved.get(bid, 0.0) - res._reserved
            res._settled = True

    def would_allow(self, tool_name: str,
                    estimate_seconds: float = 0.0) -> tuple[bool, str]:
        """Non-mutating preview. Two callers can both see it pass and then
        over-spend, so use :meth:`reserve` for the actual gate."""
        budget_id = self.config.budget_for(tool_name)
        if budget_id is None:
            return True, "ok_untracked"
        if self.config.tightened:
            return False, "compute_budget_disabled_tightened"
        ceiling = self.config.ceiling_for(budget_id)
        if ceiling is None:
            return True, "ok_no_ceiling"
        with self._lock:
            left = ceiling - (self.spent.get(budget_id, 0.0)
                              + self._reserved.get(budget_id, 0.0))
        return (True, "ok") if left > 0 else (False, "compute_budget_exhausted")

    def enter_tightened_mode(self) -> None:
        self.config.tightened = True

    def exit_tightened_mode(self) -> None:
        self.config.tightened = False

    def remaining(self, budget_id: str) -> float | None:
        ceiling = self.config.ceiling_for(budget_id)
        if ceiling is None:
            return None
        with self._lock:
            return ceiling - (self.spent.get(budget_id, 0.0)
                              + self._reserved.get(budget_id, 0.0))

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "spent": {k: round(v, 6) for k, v in self.spent.items()},
                "ceilings": {k: float(v) for k, v in self.config.ceilings.items()},
                "tightened": self.config.tightened,
            }
