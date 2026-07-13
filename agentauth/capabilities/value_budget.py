"""Session-level cumulative *value* budget -- sums the actual quantities in
tool-call arguments (dollars moved, headcount touched, ...) against a ceiling,
instead of counting calls.

This is the cumulative/semantic complement to the per-(tool,target) call
budget in ``scoping/tools/tool_call_budget.py``. The call budget catches
same-target repetition; this catches aggregate volume that exceeds what the
*requesting human* is authorized to move, no matter how it's spread across
tools or targets. Two properties matter:

  - Tool-agnostic: ``issue_payroll_bonus.bonus_amount`` and the legacy
    connector's ``amount`` both debit the same ``usd_payout`` budget, so the
    ceiling can't be evaded by switching tools. It composes with (does not
    replace) the tool-capability lease.
  - Requester-inherited ceiling: the limit is a property of the requester's
    own authority, seeded from outside the agent's reasoning loop -- "inherit
    a budget, not just a yes/no capability." The agent cannot raise it.

Money is handled with :class:`decimal.Decimal` throughout (parsed via
``Decimal(str(x))`` and quantized to :data:`MONEY_QUANTUM`); a raw ``float``
never touches an accumulation or a comparison, so structuring an attack around
binary-float rounding is not possible.

Concurrency: parallel tool calls that each pass a read-only ``would_allow`` and
then each ``commit`` would over-spend (a check/commit TOCTOU). Use the atomic
:meth:`SessionValueBudget.reserve` gate -- it checks the projected total AND
records the reservation under one lock -- then :meth:`ValueReservation.commit`
or :meth:`ValueReservation.release` once the call is confirmed or blocked.
``would_allow``/``commit`` are retained (lock-guarded) for the legacy
check-then-commit path and for read-only monitoring passes.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from agentauth.capabilities.budget import (
    BudgetType,
    budget_attr as _budget_attr,
    select_budgets,
)

# Currency scale: money is accumulated and compared at cent precision.
MONEY_QUANTUM = Decimal("0.01")


def _money(value: Any) -> Decimal:
    """Coerce a scalar to a quantized :class:`Decimal` WITHOUT going via float."""
    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def value_budget_config_from_mandate(
    mandate: Any,
    *,
    tracked: Mapping[str, tuple[str, str]],
    supersession_eligible: frozenset[str] | set[str] | None = None,
    tightened: bool = False,
) -> ValueBudgetConfig:
    """Build a live *value* (money) session ledger from a signed mandate.

    Mandates/capability tokens are the cryptographic grant: they describe which
    budget IDs and ceilings were delegated. They do not, by themselves, remember
    prior tool calls. This helper turns the signed **USD** limits into the
    stateful layer-2 ledger that catches fragmented-but-individually-valid
    effects such as two $999 payments against one $1000 authorization.

    Only ``BudgetType.USD_LIMIT`` budgets are consumed here — the value ledger
    sums monetary quantities at cent precision, so it is the wrong home for a
    call-count, token, compute, or byte grant. Those are dispatched to their own
    enforcers by :func:`agentauth.capabilities.session_budgets_from_mandate`;
    routing them through here (the prior behavior) silently reinterpreted, e.g.,
    a "3 tool calls" grant as a "$3.00" ceiling that nothing ever debited.
    """
    budgets = _budget_attr(mandate, "budgets") or []
    ceilings: dict[str, str] = {}
    for budget in select_budgets(budgets, BudgetType.USD_LIMIT):
        budget_id = str(_budget_attr(budget, "budget_id"))
        limit = _money(_budget_attr(budget, "limit"))
        remaining = _money(_budget_attr(budget, "remaining"))
        ceilings[budget_id] = str(min(limit, remaining))
    return ValueBudgetConfig(
        tracked=dict(tracked),
        ceilings=ceilings,
        supersession_eligible=frozenset(supersession_eligible or frozenset()),
        tightened=tightened,
    )


def session_value_budget_from_mandate(
    mandate: Any,
    *,
    tracked: Mapping[str, tuple[str, str]],
    supersession_eligible: frozenset[str] | set[str] | None = None,
    tightened: bool = False,
) -> SessionValueBudget:
    """Create a fresh per-session cumulative budget from a mandate."""
    return SessionValueBudget(
        config=value_budget_config_from_mandate(
            mandate,
            tracked=tracked,
            supersession_eligible=supersession_eligible,
            tightened=tightened,
        )
    )


@dataclass
class ValueBudgetConfig:
    # tool_name -> (arg_name carrying the quantity, budget_id it debits)
    tracked: dict[str, tuple[str, str]] = field(default_factory=dict)
    # budget_id -> ceiling (the requester-inherited limit). Accepts int/float/
    # str/Decimal; coerced to Decimal on read (never accumulated as float).
    ceilings: dict[str, Any] = field(default_factory=dict)
    # tools where a same-idempotency-key call replaces (net delta) rather than
    # adds -- see ToolCallBudgetConfig.supersession_eligible for the safety
    # rationale (a replace can only ever reduce a total).
    supersession_eligible: frozenset[str] = field(default_factory=frozenset)
    tightened: bool = False

    def tracked_for(self, tool_name: str) -> tuple[str, str] | None:
        return self.tracked.get(tool_name)

    def ceiling_for(self, budget_id: str) -> Decimal | None:
        raw = self.ceilings.get(budget_id)
        return None if raw is None else _money(raw)


@dataclass
class ValueReservation:
    """Handle for a value reserved atomically at check-time.

    ``allowed`` is the gate decision; when True the caller must finalize with
    :meth:`commit` (call confirmed) or roll back with :meth:`release` (call
    blocked/failed). Both are idempotent.
    """

    allowed: bool
    reason: str
    _budget: SessionValueBudget | None = None
    _budget_id: str | None = None
    _net: Decimal = Decimal(0)
    _amount: Decimal = Decimal(0)
    _idempotency_key: str | None = None
    _settled: bool = False

    def commit(self) -> None:
        if self._budget is not None:
            self._budget._commit_reservation(self)

    def release(self) -> None:
        if self._budget is not None:
            self._budget._release_reservation(self)


@dataclass
class SessionValueBudget:
    """One instance per session (the instance *is* the session's ledger)."""

    config: ValueBudgetConfig = field(default_factory=ValueBudgetConfig)
    spent: dict[str, Decimal] = field(default_factory=dict)  # budget_id -> cumulative
    # (budget_id, idempotency_key) -> amount already booked for that effect, so
    # a superseding call nets (new - prior) instead of adding.
    _effects: dict[tuple[str, str], Decimal] = field(default_factory=dict)
    # budget_id -> net value reserved but not yet committed/released.
    _reserved: dict[str, Decimal] = field(default_factory=dict)
    _lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)

    def _amount(self, tool_name: str, args: dict[str, Any]) -> tuple[str, Decimal] | None:
        spec = self.config.tracked_for(tool_name)
        if spec is None:
            return None
        arg_name, budget_id = spec
        raw = args.get(arg_name)
        if not isinstance(raw, (int, float, str, Decimal)) or isinstance(raw, bool):
            return None
        try:
            return budget_id, _money(raw)
        except (ValueError, ArithmeticError):
            return None

    def _prior_effect(
        self, tool_name: str, budget_id: str, args: dict[str, Any]
    ) -> tuple[tuple[str, str], Decimal] | None:
        if tool_name not in self.config.supersession_eligible:
            return None
        raw = args.get("_idempotency_key")
        if not isinstance(raw, str) or not raw.strip():
            return None
        ekey = (budget_id, raw.strip())
        if ekey not in self._effects:
            return None
        return ekey, self._effects[ekey]

    def would_allow(self, tool_name: str, args: dict[str, Any]) -> tuple[bool, str]:
        """Non-mutating: safe from a monitoring/dry-run pass. Reflects (but does
        not consume) any outstanding reservations. NOTE: this is a *preview* --
        two callers can both see it pass and then over-spend; use
        :meth:`reserve` for the actual gate."""
        parsed = self._amount(tool_name, args)
        if parsed is None:
            return True, "ok_untracked"
        if self.config.tightened:
            return False, "value_budget_disabled_tightened"
        budget_id, amount = parsed
        # A negative tracked value must never book: a debit of -X would drop the running
        # total and open headroom to later exceed the ceiling by X. (A supersession
        # *reduction* is a negative NET of two positive amounts, handled below, not a
        # negative raw amount.)
        if amount < 0:
            return False, "value_budget_negative_amount"
        ceiling = self.config.ceiling_for(budget_id)
        if ceiling is None:
            return True, "ok_no_ceiling"
        prior = self._prior_effect(tool_name, budget_id, args)
        prior_amount = prior[1] if prior is not None else Decimal(0)
        with self._lock:
            projected = (
                self.spent.get(budget_id, Decimal(0))
                + self._reserved.get(budget_id, Decimal(0))
                - prior_amount
                + amount
            )
        if projected > ceiling:
            return False, "value_budget_exceeded"
        return True, "ok"

    def reserve(self, tool_name: str, args: dict[str, Any]) -> ValueReservation:
        """Atomic gate: check the projected total against the ceiling AND record
        the reservation under one lock. Returns a :class:`ValueReservation`;
        when ``allowed`` is True the caller MUST later ``commit`` or ``release``
        it. Defeats the parallel check/commit TOCTOU."""
        parsed = self._amount(tool_name, args)
        if parsed is None:
            return ValueReservation(True, "ok_untracked")
        if self.config.tightened:
            return ValueReservation(False, "value_budget_disabled_tightened")
        budget_id, amount = parsed
        if amount < 0:  # negative debits open ceiling headroom — reject (see would_allow)
            return ValueReservation(False, "value_budget_negative_amount")
        ceiling = self.config.ceiling_for(budget_id)
        raw_key = args.get("_idempotency_key")
        idem = raw_key.strip() if isinstance(raw_key, str) and raw_key.strip() else None
        with self._lock:
            prior = self._prior_effect(tool_name, budget_id, args)
            prior_amount = prior[1] if prior is not None else Decimal(0)
            net = amount - prior_amount
            if ceiling is not None:
                projected = (
                    self.spent.get(budget_id, Decimal(0))
                    + self._reserved.get(budget_id, Decimal(0))
                    + net
                )
                if projected > ceiling:
                    return ValueReservation(False, "value_budget_exceeded")
            self._reserved[budget_id] = self._reserved.get(budget_id, Decimal(0)) + net
            return ValueReservation(
                True,
                "ok",
                _budget=self,
                _budget_id=budget_id,
                _net=net,
                _amount=amount,
                _idempotency_key=idem,
            )

    def _commit_reservation(self, res: ValueReservation) -> None:
        with self._lock:
            if res._settled or res._budget_id is None:
                res._settled = True
                return
            budget_id = res._budget_id
            self._reserved[budget_id] = self._reserved.get(budget_id, Decimal(0)) - res._net
            self.spent[budget_id] = self.spent.get(budget_id, Decimal(0)) + res._net
            if res._idempotency_key is not None:
                self._effects[(budget_id, res._idempotency_key)] = res._amount
            res._settled = True

    def _release_reservation(self, res: ValueReservation) -> None:
        with self._lock:
            if res._settled or res._budget_id is None:
                res._settled = True
                return
            budget_id = res._budget_id
            self._reserved[budget_id] = self._reserved.get(budget_id, Decimal(0)) - res._net
            res._settled = True

    def commit(self, tool_name: str, args: dict[str, Any]) -> None:
        """Debit the budget directly (legacy check-then-commit path). Call only
        after a call is confirmed non-blocked. Lock-guarded, but NOT atomic with
        an earlier ``would_allow`` -- prefer :meth:`reserve` for the gate."""
        parsed = self._amount(tool_name, args)
        if parsed is None:
            return
        budget_id, amount = parsed
        if amount < 0:  # never book a negative debit (would open ceiling headroom)
            return
        with self._lock:
            prior = self._prior_effect(tool_name, budget_id, args)
            prior_amount = prior[1] if prior is not None else Decimal(0)
            self.spent[budget_id] = (
                self.spent.get(budget_id, Decimal(0)) - prior_amount + amount
            )
            raw = args.get("_idempotency_key")
            if (
                tool_name in self.config.supersession_eligible
                and isinstance(raw, str)
                and raw.strip()
            ):
                self._effects[(budget_id, raw.strip())] = amount

    def enter_tightened_mode(self) -> None:
        self.config.tightened = True

    def exit_tightened_mode(self) -> None:
        self.config.tightened = False

    def remaining(self, budget_id: str) -> Decimal | None:
        ceiling = self.config.ceiling_for(budget_id)
        if ceiling is None:
            return None
        with self._lock:
            return ceiling - (
                self.spent.get(budget_id, Decimal(0))
                + self._reserved.get(budget_id, Decimal(0))
            )

    def to_dict(self) -> dict[str, Any]:
        # Money is emitted as exact decimal strings (never re-coerced through
        # float) so the ledger round-trips without binary-float drift.
        with self._lock:
            return {
                "spent": {k: str(v) for k, v in self.spent.items()},
                "ceilings": {
                    k: str(_money(v)) for k, v in self.config.ceilings.items()
                },
                "tightened": self.config.tightened,
            }
