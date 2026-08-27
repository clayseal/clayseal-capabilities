"""Capability budget shapes, canonical home: ``agentauth.core.budget``.

Kept as a re-export so ``agentauth.capabilities.budget`` remains a valid import
path; the contract itself lives in the core package (receipts consumes it
without this layer installed).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from agentauth.core.budget import BudgetType, CapabilityBudget

__all__ = [
    "BudgetType",
    "CapabilityBudget",
    "budget_attr",
    "budget_type_of",
    "select_budgets",
]


def budget_attr(raw: Any, name: str) -> Any:
    """Read a field off a budget that may be a dataclass or a plain mapping."""
    if isinstance(raw, Mapping):
        return raw.get(name)
    return getattr(raw, name)


def budget_type_of(raw: Any) -> BudgetType:
    """Normalize a budget's ``budget_type`` to a :class:`BudgetType`, whether it
    arrives as the enum, its string value (dict form), or a name."""
    value = budget_attr(raw, "budget_type")
    if isinstance(value, BudgetType):
        return value
    text = str(value)
    try:
        return BudgetType(text)
    except ValueError:
        return BudgetType[text]  # accept the member NAME too; raises KeyError if unknown


def select_budgets(budgets: Iterable[Any], wanted: BudgetType) -> list[Any]:
    """Return only the budgets of a given type, the dispatch primitive that keeps
    a call-count grant from ever being summed as dollars, and vice versa."""
    return [b for b in budgets if budget_type_of(b) == wanted]
