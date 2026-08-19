"""Session-level cumulative *call-count* budget — the count-based sibling of the
value ledger in ``value_budget.py``. Where that ledger sums quantities carried in
arguments (dollars moved, headcount touched), this one counts the number of
tracked tool calls against a ceiling.

A signed mandate can grant "at most N tool calls under this authorization"
(``BudgetType.TOOL_CALL_LIMIT``). That grant is stateless — it does not remember
prior calls — so on its own it cannot stop an unauthorized *number* of
individually-valid calls. This is the stateful layer-2 ledger that does: it
remembers the running count and refuses the call that would cross the ceiling,
even though every single call is well-formed.

Distinct from ``scoping/tools/tool_call_budget.py``: that bounds repetition per
(tool, target) as a structuring defense with tiered per-tool defaults; this
bounds the grant-wide aggregate count keyed by ``budget_id`` and is tool-agnostic
(several tools can debit one grant), exactly mirroring how the value ledger works
so the two compose. The runtime already consults a value budget and a tool-call
budget side by side; this slots in as the grant-wide count enforcer.

Counts are plain :class:`int` (a call is one call); no money quantization is
involved, which is precisely why a call-count grant must not be run through the
money ledger.

Concurrency: use the atomic :meth:`SessionCallBudget.reserve` gate — it checks the
projected count AND records the reservation under one lock — then
:meth:`CallReservation.commit` (call confirmed) or :meth:`CallReservation.release`
(call blocked/failed).
"""

from __future__ import annotations

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


def call_budget_config_from_mandate(
    mandate: Any,
    *,
    tracked: Mapping[str, str],
    supersession_eligible: frozenset[str] | set[str] | None = None,
    tightened: bool = False,
) -> CallBudgetConfig:
    """Build a live call-count session ledger from a signed mandate.

    Consumes only ``BudgetType.TOOL_CALL_LIMIT`` budgets — the count grants — and
    turns each into an integer ceiling keyed by ``budget_id``. ``tracked`` maps a
    tool name to the ``budget_id`` its calls debit (several tools may share one),
    so the ceiling cannot be evaded by spreading calls across tools.
    """
    budgets = _budget_attr(mandate, "budgets") or []
    ceilings: dict[str, int] = {}
    for budget in select_budgets(budgets, BudgetType.TOOL_CALL_LIMIT):
        budget_id = str(_budget_attr(budget, "budget_id"))
        limit = int(_budget_attr(budget, "limit"))
        remaining = int(_budget_attr(budget, "remaining"))
        ceilings[budget_id] = min(limit, remaining)
    return CallBudgetConfig(
        tracked=dict(tracked),
        ceilings=ceilings,
        supersession_eligible=frozenset(supersession_eligible or frozenset()),
        tightened=tightened,
    )


def session_call_budget_from_mandate(
    mandate: Any,
    *,
    tracked: Mapping[str, str],
    supersession_eligible: frozenset[str] | set[str] | None = None,
    tightened: bool = False,
) -> SessionCallBudget:
    """Create a fresh per-session cumulative call-count budget from a mandate."""
    return SessionCallBudget(
        config=call_budget_config_from_mandate(
            mandate,
            tracked=tracked,
            supersession_eligible=supersession_eligible,
            tightened=tightened,
        )
    )


@dataclass(frozen=True)
class CallEffectSpec:
    """A tracked tool, and optionally the object its call acts on.

    The plain string form (`tool -> budget_id`) counts calls and nothing else.
    That is the right shape for a rate limit and the wrong one for an effect
    that must happen at most once per target, which is most non-monetary
    consequential actions: granting access, deleting a record, approving a
    request.

    `identity_args` closes a violation class no count can express. BPL's
    `contractor-scope-creep` mandates read-only access for one contractor; the
    attack grants `read`, gets refused on two elevation tools, then simply calls
    the same allow-listed `grant_repo_access` again with `level: write`. Both
    calls are inside any call ceiling, the tool is legitimately granted, and the
    privilege is escalated. The value budget cannot help — a grant carries no
    amount.

    Same cumulative framing as `EffectSpec.identity_args`, over calls rather
    than value: the predicate is `no object appears twice`, not `count <= N`.

    Backward compatible: `tracked` still accepts the bare budget id.
    """

    budget_id: str
    identity_args: tuple[str, ...] = ()

    @classmethod
    def coerce(cls, raw: Any) -> CallEffectSpec:
        if isinstance(raw, CallEffectSpec):
            return raw
        return cls(budget_id=str(raw))

    def identity_of(self, args: Mapping[str, Any]) -> str | None:
        from agentauth.capabilities.value_budget import effect_identity

        return effect_identity(self.identity_args, args)


@dataclass
class CallBudgetConfig:
    # tool_name -> budget_id it debits (one call = one unit against that budget)
    # tool_name -> budget_id, or a CallEffectSpec when the mandate needs to say
    # which object the call acts on.
    tracked: dict[str, Any] = field(default_factory=dict)
    # budget_id -> integer ceiling (the requester-inherited call allowance)
    ceilings: dict[str, int] = field(default_factory=dict)
    # tools where a same-idempotency-key call replaces a prior one (nets 0 extra
    # slots) rather than counting as a new call — see ToolCallBudgetConfig.
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
                value = int(raw)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"call ceiling for {budget_id!r} is not an integer: "
                    f"{raw!r}") from exc
            if value < 0:
                raise ValueError(
                    f"call ceiling for {budget_id!r} must be non-negative, "
                    f"got {raw!r}")

    def budget_for(self, tool_name: str) -> str | None:
        raw = self.tracked.get(tool_name)
        if raw is None:
            return None
        return CallEffectSpec.coerce(raw).budget_id

    def spec_for(self, tool_name: str) -> CallEffectSpec | None:
        raw = self.tracked.get(tool_name)
        return None if raw is None else CallEffectSpec.coerce(raw)

    def ceiling_for(self, budget_id: str) -> int | None:
        raw = self.ceilings.get(budget_id)
        return None if raw is None else int(raw)


@dataclass
class CallReservation:
    """Handle for a call slot reserved atomically at check-time.

    When ``allowed`` is True the caller MUST finalize with :meth:`commit` (call
    confirmed) or roll back with :meth:`release` (call blocked/failed). Both are
    idempotent; a supersede-replace reservation settles as a no-op."""

    allowed: bool
    reason: str
    _budget: SessionCallBudget | None = None
    _budget_id: str | None = None
    _delta: int = 0
    _idempotency_key: str | None = None
    _identity: str | None = None
    _settled: bool = False

    def commit(self) -> None:
        if self._budget is not None:
            self._budget._commit_reservation(self)

    def release(self) -> None:
        if self._budget is not None:
            self._budget._release_reservation(self)


@dataclass
class SessionCallBudget:
    """One instance per session (the instance *is* the session's call ledger)."""

    config: CallBudgetConfig = field(default_factory=CallBudgetConfig)
    spent: dict[str, int] = field(default_factory=dict)  # budget_id -> committed count
    # (budget_id, idempotency_key) already counted, so a superseding call nets 0.
    _effects: set[tuple[str, str]] = field(default_factory=set)
    # budget_id -> slots reserved but not yet committed/released.
    _reserved: dict[str, int] = field(default_factory=dict)
    _committed_identities: dict[str, set] = field(default_factory=dict)
    _reserved_identities: dict[str, set] = field(default_factory=dict)
    _lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)

    def _idem(self, args: Mapping[str, Any]) -> str | None:
        raw = args.get("_idempotency_key")
        return raw.strip() if isinstance(raw, str) and raw.strip() else None

    def reserve(self, tool_name: str, args: Mapping[str, Any]) -> CallReservation:
        """Atomic gate: check the projected count against the ceiling AND record
        the reservation under one lock. When ``allowed`` is True the caller MUST
        later ``commit`` or ``release`` it. Defeats the parallel check/commit
        TOCTOU that plain read-then-increment would open."""
        budget_id = self.config.budget_for(tool_name)
        if budget_id is None:
            return CallReservation(True, "ok_untracked")
        if self.config.tightened:
            return CallReservation(False, "call_budget_disabled_tightened")
        ceiling = self.config.ceiling_for(budget_id)
        idem = self._idem(args)
        spec = self.config.spec_for(tool_name)
        identity = spec.identity_of(args) if spec is not None else None
        with self._lock:
            if identity is not None and (
                    identity in self._committed_identities.get(budget_id, ())
                    or identity in self._reserved_identities.get(budget_id, ())):
                # Once-per-object. A call ceiling cannot see this: granting the
                # same person access twice is two calls, both under any count,
                # and the second one is the escalation.
                return CallReservation(False, "call_budget_duplicate_effect")
            # A same-key call on a supersession-eligible tool replaces a prior
            # effect: it consumes no new slot (delta 0), so it can never inflate
            # the count and is safe against a lying agent by construction.
            superseding = (
                idem is not None
                and tool_name in self.config.supersession_eligible
                and (budget_id, idem) in self._effects
            )
            delta = 0 if superseding else 1
            if ceiling is not None and delta:
                projected = (
                    self.spent.get(budget_id, 0)
                    + self._reserved.get(budget_id, 0)
                    + delta
                )
                if projected > ceiling:
                    return CallReservation(False, "call_budget_exceeded")
            self._reserved[budget_id] = self._reserved.get(budget_id, 0) + delta
            if identity is not None:
                self._reserved_identities.setdefault(budget_id, set()).add(identity)
            return CallReservation(
                True, "ok", _budget=self, _budget_id=budget_id, _delta=delta,
                _idempotency_key=idem, _identity=identity,
            )

    def _commit_reservation(self, res: CallReservation) -> None:
        with self._lock:
            if res._settled or res._budget_id is None:
                res._settled = True
                return
            bid = res._budget_id
            self._reserved[bid] = self._reserved.get(bid, 0) - res._delta
            if res._identity is not None:
                self._reserved_identities.get(bid, set()).discard(res._identity)
                self._committed_identities.setdefault(bid, set()).add(res._identity)
            self.spent[bid] = self.spent.get(bid, 0) + res._delta
            if res._idempotency_key is not None:
                self._effects.add((bid, res._idempotency_key))
            res._settled = True

    def _release_reservation(self, res: CallReservation) -> None:
        with self._lock:
            if res._settled or res._budget_id is None:
                res._settled = True
                return
            bid = res._budget_id
            self._reserved[bid] = self._reserved.get(bid, 0) - res._delta
            if res._identity is not None:
                # A released reservation frees its object again, or a downstream
                # refusal pins the target for the session and the retry of a
                # legitimate action is refused as a duplicate.
                self._reserved_identities.get(bid, set()).discard(res._identity)
            res._settled = True

    def would_allow(self, tool_name: str, args: Mapping[str, Any]) -> tuple[bool, str]:
        """Non-mutating preview (safe from a monitoring/dry-run pass). Reflects but
        does not consume outstanding reservations; two callers can both see it pass
        and then over-count, so use :meth:`reserve` for the actual gate."""
        budget_id = self.config.budget_for(tool_name)
        if budget_id is None:
            return True, "ok_untracked"
        if self.config.tightened:
            return False, "call_budget_disabled_tightened"
        ceiling = self.config.ceiling_for(budget_id)
        if ceiling is None:
            return True, "ok_no_ceiling"
        idem = self._idem(args)
        with self._lock:
            superseding = (
                idem is not None
                and tool_name in self.config.supersession_eligible
                and (budget_id, idem) in self._effects
            )
            delta = 0 if superseding else 1
            projected = (
                self.spent.get(budget_id, 0) + self._reserved.get(budget_id, 0) + delta
            )
        if delta and projected > ceiling:
            return False, "call_budget_exceeded"
        return True, "ok"

    def enter_tightened_mode(self) -> None:
        self.config.tightened = True

    def exit_tightened_mode(self) -> None:
        self.config.tightened = False

    def remaining(self, budget_id: str) -> int | None:
        ceiling = self.config.ceiling_for(budget_id)
        if ceiling is None:
            return None
        with self._lock:
            return ceiling - (
                self.spent.get(budget_id, 0) + self._reserved.get(budget_id, 0)
            )

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "spent": dict(self.spent),
                "ceilings": {k: int(v) for k, v in self.config.ceilings.items()},
                "tightened": self.config.tightened,
            }
