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

Enforcement hook: like the call budget, this is checked in the gateway's
pre-execution violations pass and *committed* only after a call is confirmed
non-blocked (see mcp.py). It is deliberately NOT wired through the
reservation_callback: that path runs inside ``record()``, which on the
gateway fires *after* the tool handler already executed -- too late to block.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ValueBudgetConfig:
    # tool_name -> (arg_name carrying the quantity, budget_id it debits)
    tracked: dict[str, tuple[str, str]] = field(default_factory=dict)
    # budget_id -> ceiling (the requester-inherited limit)
    ceilings: dict[str, float] = field(default_factory=dict)
    # tools where a same-idempotency-key call replaces (net delta) rather than
    # adds -- see ToolCallBudgetConfig.supersession_eligible for the safety
    # rationale (a replace can only ever reduce a total).
    supersession_eligible: frozenset[str] = field(default_factory=frozenset)
    tightened: bool = False

    def tracked_for(self, tool_name: str) -> tuple[str, str] | None:
        return self.tracked.get(tool_name)


@dataclass
class SessionValueBudget:
    """One instance per session (the instance *is* the session's ledger)."""

    config: ValueBudgetConfig = field(default_factory=ValueBudgetConfig)
    spent: dict[str, float] = field(default_factory=dict)  # budget_id -> cumulative
    # (budget_id, idempotency_key) -> amount already booked for that effect, so
    # a superseding call nets (new - prior) instead of adding.
    _effects: dict[tuple[str, str], float] = field(default_factory=dict)

    def _amount(self, tool_name: str, args: dict[str, Any]) -> tuple[str, float] | None:
        spec = self.config.tracked_for(tool_name)
        if spec is None:
            return None
        arg_name, budget_id = spec
        raw = args.get(arg_name)
        if not isinstance(raw, (int, float)):
            return None
        return budget_id, float(raw)

    def _prior_effect(
        self, tool_name: str, budget_id: str, args: dict[str, Any]
    ) -> tuple[tuple[str, str], float] | None:
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
        """Non-mutating: safe from a monitoring/dry-run pass."""
        parsed = self._amount(tool_name, args)
        if parsed is None:
            return True, "ok_untracked"
        if self.config.tightened:
            return False, "value_budget_disabled_tightened"
        budget_id, amount = parsed
        ceiling = self.config.ceilings.get(budget_id)
        if ceiling is None:
            return True, "ok_no_ceiling"
        prior = self._prior_effect(tool_name, budget_id, args)
        prior_amount = prior[1] if prior is not None else 0.0
        projected = self.spent.get(budget_id, 0.0) - prior_amount + amount
        if projected > ceiling:
            return False, "value_budget_exceeded"
        return True, "ok"

    def commit(self, tool_name: str, args: dict[str, Any]) -> None:
        """Debit the budget. Call only after a call is confirmed non-blocked."""
        parsed = self._amount(tool_name, args)
        if parsed is None:
            return
        budget_id, amount = parsed
        prior = self._prior_effect(tool_name, budget_id, args)
        prior_amount = prior[1] if prior is not None else 0.0
        self.spent[budget_id] = self.spent.get(budget_id, 0.0) - prior_amount + amount
        raw = args.get("_idempotency_key")
        if tool_name in self.config.supersession_eligible and isinstance(raw, str) and raw.strip():
            self._effects[(budget_id, raw.strip())] = amount

    def enter_tightened_mode(self) -> None:
        self.config.tightened = True

    def exit_tightened_mode(self) -> None:
        self.config.tightened = False

    def remaining(self, budget_id: str) -> float | None:
        ceiling = self.config.ceilings.get(budget_id)
        if ceiling is None:
            return None
        return ceiling - self.spent.get(budget_id, 0.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "spent": dict(self.spent),
            "ceilings": dict(self.config.ceilings),
            "tightened": self.config.tightened,
        }
