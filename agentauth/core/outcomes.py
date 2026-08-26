from __future__ import annotations

from enum import Enum


class DecisionOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    PENDING_APPROVAL = "pending_approval"
    PENDING_STEP_UP = "pending_step_up"
    ALLOW_WITH_OBLIGATIONS = "allow_with_obligations"
    ALLOW_WITH_REVIEW = "allow_with_review"
    BUDGET_RESERVATION_REQUIRED = "budget_reservation_required"

    @classmethod
    def supported_values(cls) -> tuple[str, ...]:
        """Portable outcome vocabulary (L3-2)."""
        return tuple(item.value for item in cls)
