"""A value budget with a rolling window: "no more than $X per 24 hours".

WHY THIS DID NOT EXIST, AND WHY IT HAD TO

Two rungs already bound aggregates and neither can express the rule most business
policies are actually written as.

- `SessionValueBudget` sums an amount and never forgets. It enforces "no more
  than $X **ever**", which is the right shape for one task and the wrong shape
  for a standing authority.
- `SessionVelocity` has a rolling window and counts ACTIONS. It enforces "no more
  than N calls per hour" and has no notion of amount.

Nothing windowed a VALUE, so "no more than $10,000 per 24 hours" had to be
approximated by a session ceiling, and `benchmarks/bpl/scenarios/*` says so in as
many words: *"Session budget approximates the rolling ceiling for a single
episode (aspirational for true time-skewed ledgers)."*

The approximation is not conservative, it is wrong in both directions at once,
and `rolling-window-hour-skew` is the measured case. The benign script pays
$2,000, advances the clock 24 hours, and pays $2,000 again: legal under a rolling
window, because the two payments never coexist in one. The attack advances only 6
hours, so both land inside one window. A session budget sees $4,000 either way.
It refused the benign script, which is the one scenario in 132 where this gateway
loses real work, and it "contained" the attack for a reason that had nothing to do
with the rule.

WHAT THIS IS

`SessionValueBudget` with an eviction pass. Everything about reservations,
supersession, identity, Decimal arithmetic and the TOCTOU-free reserve/commit
protocol is inherited unchanged, because that logic is load-bearing and a second
copy of it is a second thing to keep in step. This adds one idea: a timestamped
ledger, pruned to the window before any decision reads the running total.

THE CLOCK IS INJECTED, AND THAT IS THE POINT

`clock` defaults to `time.monotonic` and must be replaceable. A rolling window is
only testable, replayable and auditable if the caller controls time: a benchmark
advances a simulated clock, a replay pins one to a recorded trace, and a
deployment reads the real one. A windowed control with a hardcoded clock cannot be
verified, which makes it a control nobody should trust.

WHAT AGES OUT

An evicted entry stops counting toward the ceiling, and its idempotency key and
object identity are released with it. That is deliberate: outside the window the
effect did not happen as far as this ceiling is concerned, so a rule like "no more
than three payments to the same vendor per day" frees the vendor tomorrow. Keeping
the identity forever would make the window apply to amounts and not to identities,
which is the sort of half-applied control this repository keeps finding.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from agentauth.capabilities.value_budget import (
    SessionValueBudget,
    ValueReservation,
)


@dataclass(frozen=True)
class _Entry:
    """One committed effect, with everything needed to un-commit it on eviction."""

    at: float
    budget_id: str
    net: Decimal
    idempotency_key: str | None = None
    identity: Any = None


@dataclass
class WindowedValueBudget(SessionValueBudget):
    """A value budget whose ceiling applies over a rolling window per budget id.

    `windows` maps a budget id to a window in seconds. A budget id with no entry
    has NO window and behaves exactly as `SessionValueBudget` does, so adding
    this class to an existing configuration changes nothing until a window is
    declared. That default matters: every published number was measured without
    one.
    """

    windows: dict[str, float] = field(default_factory=dict)
    #: Seconds, monotonic. Replaceable, and see the module docstring for why.
    clock: Callable[[], float] = time.monotonic
    _ledger: list[_Entry] = field(default_factory=list, repr=False)
    _wlock: Any = field(default_factory=threading.RLock, repr=False, compare=False)

    def __post_init__(self) -> None:
        parent = getattr(super(), "__post_init__", None)
        if parent is not None:
            parent()
        for budget_id, window in self.windows.items():
            if not isinstance(window, (int, float)) or window <= 0:
                # A malformed window is a control-plane bug, and every way of
                # absorbing one quietly is worse than refusing it: a window of 0
                # or a negative one evicts everything immediately and turns the
                # ceiling off while continuing to look like a ceiling.
                raise ValueError(
                    f"window for budget {budget_id!r} must be a positive number "
                    f"of seconds, got {window!r}"
                )

    # ------------------------------------------------------------------ #
    # Eviction
    # ------------------------------------------------------------------ #
    def _prune(self) -> None:
        """Drop entries outside their window and recompute the running totals.

        Called before every decision rather than on a timer, so there is no
        window during which the ceiling is stale. Recomputing from the ledger
        rather than subtracting is deliberate: subtraction accumulates rounding
        and a Decimal total that drifts is a ceiling that drifts.
        """
        if not self.windows:
            return
        now = self.clock()
        with self._wlock, self._lock:
            kept: list[_Entry] = []
            evicted: list[_Entry] = []
            for entry in self._ledger:
                window = self.windows.get(entry.budget_id)
                if window is None or (now - entry.at) < window:
                    kept.append(entry)
                else:
                    evicted.append(entry)
            if not evicted:
                return
            self._ledger = kept

            windowed = {b for b in self.windows if any(
                e.budget_id == b for e in evicted)}
            for budget_id in windowed:
                total = sum((e.net for e in kept if e.budget_id == budget_id),
                            Decimal(0))
                self.spent[budget_id] = total
            for entry in evicted:
                if entry.idempotency_key is not None:
                    self._effects.pop((entry.budget_id, entry.idempotency_key), None)
                if entry.identity is not None:
                    held = self._committed_identities.get(entry.budget_id)
                    if held is not None:
                        held.discard(entry.identity)

    # ------------------------------------------------------------------ #
    # The decision points, each pruned first
    # ------------------------------------------------------------------ #
    def would_allow(self, tool_name: str, args: dict[str, Any]) -> tuple[bool, str]:
        self._prune()
        return super().would_allow(tool_name, args)

    def reserve(self, tool_name: str, args: dict[str, Any]) -> ValueReservation:
        self._prune()
        return super().reserve(tool_name, args)

    def commit(self, tool_name: str, args: dict[str, Any]) -> None:
        self._prune()
        super().commit(tool_name, args)
        parsed = self._amount(tool_name, args)
        if parsed is None:
            return
        budget_id, amount = parsed
        if amount is None or budget_id not in self.windows:
            return
        spec = self.config.spec_for(tool_name)
        with self._wlock:
            # No idempotency key on this path. `commit` is the legacy
            # check-then-commit entry point and is documented as non-atomic; the
            # reservation path is where supersession is resolved and is where the
            # key is known. Guessing one here would let an eviction release an
            # effect key the parent never booked.
            self._ledger.append(_Entry(
                at=self.clock(), budget_id=budget_id, net=amount,
                identity=(spec.identity_of(args) if spec is not None else None),
            ))

    def _commit_reservation(self, res: ValueReservation) -> None:
        settled_before = res._settled
        budget_id = res._budget_id
        net, key, identity = res._net, res._idempotency_key, res._identity
        super()._commit_reservation(res)
        if settled_before or budget_id is None or budget_id not in self.windows:
            return
        with self._wlock:
            self._ledger.append(_Entry(at=self.clock(), budget_id=budget_id,
                                       net=net, idempotency_key=key,
                                       identity=identity))

    def remaining(self, budget_id: str) -> Decimal | None:
        self._prune()
        return super().remaining(budget_id)

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #
    def window_for(self, budget_id: str) -> float | None:
        return self.windows.get(budget_id)

    def in_window(self, budget_id: str) -> int:
        """How many committed effects currently count toward this ceiling."""
        self._prune()
        with self._wlock:
            return sum(1 for e in self._ledger if e.budget_id == budget_id)

    def to_dict(self) -> dict[str, Any]:
        out = super().to_dict()
        out["windows"] = dict(self.windows)
        out["in_window"] = {b: self.in_window(b) for b in self.windows}
        return out
