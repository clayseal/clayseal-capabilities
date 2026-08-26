"""Read-only capability budget metadata (L3-6)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class BudgetType(str, Enum):
    USD_LIMIT = "usd_limit"
    TOOL_CALL_LIMIT = "tool_call_limit"
    TOKEN_LIMIT = "token_limit"
    COMPUTE_SECONDS = "compute_seconds"
    DATA_EXPORT_BYTES = "data_export_bytes"


@dataclass
class CapabilityBudget:
    budget_id: str
    budget_type: BudgetType
    unit: str
    limit: float | int
    remaining: float | int
    scope: str | None = None
    shared: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "budget_id": self.budget_id,
            "budget_type": self.budget_type.value,
            "unit": self.unit,
            "limit": self.limit,
            "remaining": self.remaining,
            "scope": self.scope,
            "shared": self.shared,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> CapabilityBudget:
        return cls(
            budget_id=str(raw["budget_id"]),
            budget_type=BudgetType(raw["budget_type"]),
            unit=str(raw["unit"]),
            limit=raw["limit"],
            remaining=raw["remaining"],
            scope=raw.get("scope"),
            shared=bool(raw.get("shared", False)),
        )
