"""Authority lineage and transition evidence (L4-3, L3-12)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class AuthorityTransitionType(str, Enum):
    INITIAL = "initial"
    DELEGATED = "delegated"
    ATTENUATED = "attenuated"
    REVOKED_AND_RESPAWNED = "revoked_and_respawned"
    RESUMED_WITH_APPROVAL = "resumed_with_approval"
    BUDGET_REISSUED = "budget_reissued"


class AuthorityTransitionReason(str, Enum):
    INITIAL_SPAWN = "initial_spawn"
    SCOPE_NARROWED = "scope_narrowed"
    APPROVAL_GRANTED = "approval_granted"
    BUDGET_REALLOCATED = "budget_reallocated"
    RISK_ESCALATION = "risk_escalation"
    MANUAL_REVOKE = "manual_revoke"


@dataclass
class AuthorityLineage:
    authority_id: str
    authority_version: int = 1
    parent_authority_id: str | None = None
    transition_type: AuthorityTransitionType = AuthorityTransitionType.INITIAL
    transition_reason: AuthorityTransitionReason | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "authority_id": self.authority_id,
            "authority_version": self.authority_version,
            "parent_authority_id": self.parent_authority_id,
            "transition_type": self.transition_type.value,
            "transition_reason": (
                self.transition_reason.value if self.transition_reason else None
            ),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> AuthorityLineage:
        reason = raw.get("transition_reason")
        return cls(
            authority_id=str(raw["authority_id"]),
            authority_version=int(raw.get("authority_version", 1)),
            parent_authority_id=raw.get("parent_authority_id"),
            transition_type=AuthorityTransitionType(
                raw.get("transition_type", AuthorityTransitionType.INITIAL.value)
            ),
            transition_reason=(
                AuthorityTransitionReason(reason) if reason else None
            ),
        )
