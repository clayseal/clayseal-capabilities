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
    select_budgets,
)
from agentauth.capabilities.budget import (
    budget_attr as _budget_attr,
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


#: Sentinels for `effect_identity`. Hoisted out of the f-string because an
#: escape sequence inside an f-string EXPRESSION is a syntax error before
#: Python 3.12, and this package declares support from 3.10 — the module is
#: imported by `agentauth.capabilities.__init__`, so the error made the whole
#: package unimportable on 3.10/3.11. Values are unchanged.
_IDENTITY_SEP = "\u0000"
_IDENTITY_MISSING = "\u0001missing"


def effect_identity(identity_args, args: Mapping[str, Any]) -> str | None:
    """The object key an effect lands on, or None when it is repeatable.

    Shared by `EffectSpec` and `CallEffectSpec` so the two budgets cannot drift.
    Missing arguments are represented explicitly rather than skipped: two calls
    differing only in which identity field is absent must not collapse to the
    same key, or an attacker omits the field to mint a fresh identity.
    """
    if not identity_args:
        return None
    return _IDENTITY_SEP.join(
        f"{name}={args.get(name, _IDENTITY_MISSING)!r}" for name in identity_args)


@dataclass(frozen=True)
class EffectSpec:
    """What a tool call actually moves, as opposed to what its argument says.

    The tuple form (`arg_name`, `budget_id`) binds a ledger entry to a **tool
    name** and takes the argument at face value. `benchmarks/stress_aggregation.py`
    measures what that costs: against a ceiling of 100, batch amortization lands
    4,500 and unit confusion lands 9,900, both while every individual reservation
    is legal.

    Neither is a bug in the ledger. The ledger debits the number in the field,
    correctly, and cannot see that the field means cents while the ceiling means
    dollars, or that the call carries a list of fifty. Those are properties of
    the *tool*, so the mandate has to declare them.

    ``count_arg``  the argument carrying multiplicity. `total = amount * count`.
                   Closes batch amortization: a batch of 50 debits 50x.
    ``scale``      conversion into the budget's unit. Closes unit confusion: a
                   tool quoting cents against a dollar ceiling declares 0.01.
    ``unit``       documentation, and a mismatch check when two tools share a
                   budget.
    ``identity_args``
                   the arguments naming the OBJECT the effect lands on. When set,
                   the effect is once-per-object: a second commit against the same
                   identity is refused.

    `identity_args` closes a violation class the value ceiling structurally
    cannot see. `retry-storm-double-effect` in BPL pays INV-1 twice at 1200 each
    against a ceiling that has room for it; the ledger is asked "is the total
    under the limit", answers correctly, and the invoice is still paid twice. The
    scenario's own goal says "Pay each invoice once under ceiling", and until now
    a mandate had no way to write the first half of that sentence down.

    This is the same cumulative framing, with a different predicate over the same
    multiset of committed effects: not `sum <= ceiling` but `no object appears
    twice`. A per-call defense cannot express either.

    Backward compatible by construction: `tracked` still accepts the tuple, which
    is read as `EffectSpec(budget_id, amount_arg)` with count 1 and scale 1, so
    every existing mandate behaves exactly as before.
    """

    budget_id: str
    amount_arg: str
    count_arg: str = ""
    scale: Any = 1
    unit: str = ""
    identity_args: tuple[str, ...] = ()

    @classmethod
    def coerce(cls, raw: Any) -> EffectSpec:
        if isinstance(raw, EffectSpec):
            return raw
        # legacy: (arg_name, budget_id)
        arg_name, budget_id = raw
        return cls(budget_id=str(budget_id), amount_arg=str(arg_name))

    def identity_of(self, args: Mapping[str, Any]) -> str | None:
        return effect_identity(self.identity_args, args)


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
        for budget_id, raw in list(self.ceilings.items()):
            if raw is None:
                continue
            try:
                value = _money(raw)
            except (TypeError, ValueError, ArithmeticError) as exc:
                raise ValueError(
                    f"value ceiling for {budget_id!r} is not a usable amount: "
                    f"{raw!r}") from exc
            if not value.is_finite() or value < 0:
                raise ValueError(
                    f"value ceiling for {budget_id!r} must be finite and "
                    f"non-negative, got {raw!r}")

    def tracked_for(self, tool_name: str) -> tuple[str, str] | None:
        raw = self.tracked.get(tool_name)
        if raw is None:
            return None
        spec = EffectSpec.coerce(raw)
        return (spec.amount_arg, spec.budget_id)

    def spec_for(self, tool_name: str) -> EffectSpec | None:
        raw = self.tracked.get(tool_name)
        return None if raw is None else EffectSpec.coerce(raw)

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
    #: Object identity held by this reservation, when the mandate declares one.
    _identity: str | None = None
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
    # Object identities already committed / currently held, per budget. Only
    # populated for tools whose EffectSpec declares `identity_args`.
    _committed_identities: dict[str, set] = field(default_factory=dict)
    _reserved_identities: dict[str, set] = field(default_factory=dict)
    _lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)

    def _amount(
        self, tool_name: str, args: dict[str, Any]
    ) -> tuple[str, Decimal | None] | None:
        """Tri-state, because two of the states used to be conflated.

        ``None``                  the call is genuinely untracked: this tool has
                                  no money spec, or carries no amount argument.
        ``(budget_id, None)``     the call IS tracked and the amount is present
                                  but unusable — non-numeric, unparseable, or
                                  non-finite.
        ``(budget_id, Decimal)``  a usable amount.

        The middle state is the one that did not exist, and its absence was a
        fail-open. Every unparseable amount returned ``None``, callers read that
        as "untracked", and the reservation came back ``allowed=True`` with
        reason ``ok_untracked`` — no ceiling check at all. Measured against a
        ceiling of 10, all of these were allowed and booked nothing:

            '1e999'  'Infinity'  '-Infinity'  'sNaN'  '0x10'  ''  10**30

        ``1e999`` is not an exotic input. It is what an injected agent writes
        for "transfer everything", and ``10**30`` is an ordinary Python int that
        merely overflows cent-quantization. A spend ceiling that stops applying
        precisely when the amount is absurd is worse than no ceiling, because
        the rest of the stack reports that the budget rung passed.

        Non-finite values are rejected explicitly rather than left to raise.
        ``Decimal('NaN')`` quantizes without complaint and then raises
        ``InvalidOperation`` on the very next comparison — ``amount < 0`` — which
        escaped ``reserve`` unhandled and took the whole authorization call with
        it. Fail-closed on a bad amount; never fail by exception.
        """
        effect = self.config.spec_for(tool_name)
        if effect is None:
            return None
        arg_name, budget_id = effect.amount_arg, effect.budget_id
        if arg_name not in args:
            return None  # tracked tool, but this call carries no amount
        raw = args[arg_name]
        if not isinstance(raw, (int, float, str, Decimal)) or isinstance(raw, bool):
            return budget_id, None
        try:
            amount = _money(raw)
        except (ValueError, ArithmeticError, TypeError):
            return budget_id, None
        if not amount.is_finite():
            return budget_id, None

        # Multiplicity, then unit. Both are declared by the mandate because both
        # are properties of the TOOL that the argument does not carry.
        #
        # Without them the ledger debits the number in the field and a per-call
        # ceiling is defeated by arity or by denomination:
        # `benchmarks/stress_aggregation.py` lands 4,500 and 9,900 against a
        # ceiling of 100 that way, with every reservation individually legal.
        if effect.count_arg:
            raw_count = args.get(effect.count_arg, 1)
            if isinstance(raw_count, (list, tuple, set)):
                raw_count = len(raw_count)      # a batch argument IS its length
            try:
                count = _money(raw_count)
            except (TypeError, ValueError, ArithmeticError):
                return budget_id, None          # declared multiplicity, unusable
            if not count.is_finite() or count < 0:
                return budget_id, None
            amount = amount * count
        if effect.scale not in (1, "1", None):
            try:
                amount = amount * _money(effect.scale)
            except (TypeError, ValueError, ArithmeticError):
                return budget_id, None
        try:
            amount = amount.quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)
        except (ArithmeticError, ValueError):
            return budget_id, None
        return budget_id, amount

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
        if amount is None:
            return False, "value_budget_unparseable_amount"
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
        if amount is None:  # tracked but unusable: fail closed, never untracked
            return ValueReservation(False, "value_budget_unparseable_amount")
        if amount < 0:  # negative debits open ceiling headroom — reject (see would_allow)
            return ValueReservation(False, "value_budget_negative_amount")
        ceiling = self.config.ceiling_for(budget_id)
        raw_key = args.get("_idempotency_key")
        idem = raw_key.strip() if isinstance(raw_key, str) and raw_key.strip() else None
        spec = self.config.spec_for(tool_name)
        identity = spec.identity_of(args) if spec is not None else None
        with self._lock:
            if identity is not None:
                # Once-per-object. The value ceiling cannot see this: paying the
                # same invoice twice at 1200 against a ceiling with room for 3600
                # is three correct answers to the wrong question.
                #
                # An idempotency key is deliberately NOT an escape hatch here. It
                # suppresses a duplicate DEBIT, which is the opposite need: this
                # refuses a duplicate EFFECT.
                if identity in self._committed_identities.get(budget_id, ()):
                    return ValueReservation(False, "value_budget_duplicate_effect")
                if identity in self._reserved_identities.get(budget_id, ()):
                    return ValueReservation(False, "value_budget_duplicate_effect")
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
            if identity is not None:
                self._reserved_identities.setdefault(budget_id, set()).add(identity)
            return ValueReservation(
                True,
                "ok",
                _budget=self,
                _budget_id=budget_id,
                _net=net,
                _amount=amount,
                _idempotency_key=idem,
                _identity=identity,
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
            if res._identity is not None:
                self._reserved_identities.get(budget_id, set()).discard(res._identity)
                self._committed_identities.setdefault(budget_id, set()).add(res._identity)
            res._settled = True

    def _release_reservation(self, res: ValueReservation) -> None:
        with self._lock:
            if res._settled or res._budget_id is None:
                res._settled = True
                return
            budget_id = res._budget_id
            self._reserved[budget_id] = self._reserved.get(budget_id, Decimal(0)) - res._net
            if res._identity is not None:
                # A released reservation frees its object again. Without this a
                # downstream refusal would pin the identity for the session and
                # the retry of a legitimate action would be refused as a
                # duplicate — the failure that hides, because it is safe.
                self._reserved_identities.get(budget_id, set()).discard(res._identity)
            res._settled = True

    def commit(self, tool_name: str, args: dict[str, Any]) -> None:
        """Debit the budget directly (legacy check-then-commit path). Call only
        after a call is confirmed non-blocked. Lock-guarded, but NOT atomic with
        an earlier ``would_allow`` -- prefer :meth:`reserve` for the gate."""
        parsed = self._amount(tool_name, args)
        if parsed is None:
            return
        budget_id, amount = parsed
        if amount is None:  # unusable amount: book nothing rather than guess
            return
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
