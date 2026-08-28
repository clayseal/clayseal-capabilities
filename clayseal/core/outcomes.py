"""The outcome vocabulary, shared across the three layers.

An enum rather than strings because these values cross a process boundary: they
are written into decision logs and receipts that another layer reads back, so the
set has to be closed and `supported_values()` has to be able to enumerate it.

The three that matter to most callers are `ALLOW`, `DENY` and `PENDING_STEP_UP`.
The rest exist because a decision can be conditionally yes: an allow that owes an
obligation, an allow that a reviewer will see afterwards, and a call that cannot
proceed until a budget reservation is taken. Collapsing those into `ALLOW` would
lose the condition, and a caller that ignored the condition would be running an
unconditional allow while the log recorded a conditional one.
"""
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
