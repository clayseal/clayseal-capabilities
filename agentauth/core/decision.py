from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agentauth.core.outcomes import DecisionOutcome

_FULFILLED_OBLIGATION_STATUSES = {"complete", "completed", "done", "fulfilled", "satisfied"}
_BUDGET_PENDING_STATUSES = {"planned", "pending", "reserved", "held"}
_BUDGET_FINAL_STATUSES = {
    "applied",
    "committed",
    "completed",
    "failed",
    "released",
    "rejected",
    "canceled",
}
_BUDGET_RESERVATION_TYPES = {"reserve", "reserved", "hold"}
_BUDGET_CONSUMPTION_TYPES = {"consume", "consumed", "spend", "debit"}
_BUDGET_RELEASE_TYPES = {"release", "released", "credit", "refund"}

# Initial standard obligation types (L3-5); partners may define extensions.
STANDARD_OBLIGATION_TYPES = (
    "log_extra",
    "create_case",
    "require_redaction",
    "persist_handoff",
    "emit_summary",
)


def is_standard_obligation_type(obligation_type: str) -> bool:
    return obligation_type in STANDARD_OBLIGATION_TYPES


class ApprovalState(str, Enum):
    NOT_REQUIRED = "not_required"
    REQUIRED = "required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class ApprovalMetadata:
    """Optional approval workflow metadata (L3-4)."""

    approval_id: str | None = None
    approval_policy_ref: str | None = None
    approver_ref: str | None = None
    approved_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "approval_policy_ref": self.approval_policy_ref,
            "approver_ref": self.approver_ref,
            "approved_at": self.approved_at,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> ApprovalMetadata | None:
        if not raw:
            return None
        return cls(
            approval_id=raw.get("approval_id"),
            approval_policy_ref=raw.get("approval_policy_ref"),
            approver_ref=raw.get("approver_ref"),
            approved_at=raw.get("approved_at"),
        )


@dataclass
class Obligation:
    type: str
    status: str = "pending"
    details: dict[str, Any] = field(default_factory=dict)
    required_before_effect: bool = False
    required_after_effect: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "status": self.status,
            "details": self.details,
            "required_before_effect": self.required_before_effect,
            "required_after_effect": self.required_after_effect,
        }

    @classmethod
    def from_value(cls, value: str | dict[str, Any] | Obligation) -> Obligation:
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            return cls(type=value)
        return cls(
            type=str(value["type"]),
            status=str(value.get("status", "pending")),
            details=dict(value.get("details", {})),
            required_before_effect=bool(value.get("required_before_effect", False)),
            required_after_effect=bool(value.get("required_after_effect", False)),
        )

    def normalized_status(self) -> str:
        return self.status.strip().lower()

    def is_fulfilled(self) -> bool:
        return self.normalized_status() in _FULFILLED_OBLIGATION_STATUSES

    def is_pending(self) -> bool:
        return not self.is_fulfilled()

    def blocks_before_effect(self) -> bool:
        return self.required_before_effect and self.is_pending()

    def requires_after_effect_follow_up(self) -> bool:
        return self.required_after_effect and self.is_pending()


@dataclass
class ObligationSummary:
    obligations: list[Obligation] = field(default_factory=list)

    @property
    def pending(self) -> list[Obligation]:
        return [obligation for obligation in self.obligations if obligation.is_pending()]

    @property
    def blocking(self) -> list[Obligation]:
        return [obligation for obligation in self.obligations if obligation.blocks_before_effect()]

    @property
    def after_effect(self) -> list[Obligation]:
        return [
            obligation
            for obligation in self.obligations
            if obligation.requires_after_effect_follow_up()
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "all": [obligation.to_dict() for obligation in self.obligations],
            "pending": [obligation.to_dict() for obligation in self.pending],
            "blocking": [obligation.to_dict() for obligation in self.blocking],
            "after_effect": [obligation.to_dict() for obligation in self.after_effect],
        }


@dataclass
class BudgetEffect:
    budget_id: str
    effect_type: str
    amount: float | int | None = None
    status: str = "planned"
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "budget_id": self.budget_id,
            "effect_type": self.effect_type,
            "amount": self.amount,
            "status": self.status,
            "notes": self.notes,
        }

    @classmethod
    def from_value(cls, value: dict[str, Any] | BudgetEffect) -> BudgetEffect:
        if isinstance(value, cls):
            return value
        return cls(
            budget_id=str(value["budget_id"]),
            effect_type=str(value["effect_type"]),
            amount=value.get("amount"),
            status=str(value.get("status", "planned")),
            notes=value.get("notes"),
        )

    def normalized_effect_type(self) -> str:
        return self.effect_type.strip().lower()

    def normalized_status(self) -> str:
        return self.status.strip().lower()

    def is_pending(self) -> bool:
        return self.normalized_status() in _BUDGET_PENDING_STATUSES

    def is_final(self) -> bool:
        return self.normalized_status() in _BUDGET_FINAL_STATUSES

    def is_reservation(self) -> bool:
        return self.normalized_effect_type() in _BUDGET_RESERVATION_TYPES

    def is_consumption(self) -> bool:
        return self.normalized_effect_type() in _BUDGET_CONSUMPTION_TYPES

    def is_release(self) -> bool:
        return self.normalized_effect_type() in _BUDGET_RELEASE_TYPES


@dataclass
class BudgetEffectSummary:
    budget_id: str
    effects: list[BudgetEffect] = field(default_factory=list)

    @property
    def pending_effects(self) -> list[BudgetEffect]:
        return [effect for effect in self.effects if effect.is_pending()]

    @property
    def final_effects(self) -> list[BudgetEffect]:
        return [effect for effect in self.effects if effect.is_final()]

    @property
    def reservation_effects(self) -> list[BudgetEffect]:
        return [effect for effect in self.effects if effect.is_reservation()]

    @property
    def consumption_effects(self) -> list[BudgetEffect]:
        return [effect for effect in self.effects if effect.is_consumption()]

    @property
    def release_effects(self) -> list[BudgetEffect]:
        return [effect for effect in self.effects if effect.is_release()]

    def _sum_amounts(self, effects: list[BudgetEffect]) -> float:
        return float(
            sum(effect.amount for effect in effects if isinstance(effect.amount, (int, float)))
        )

    @property
    def pending_amount(self) -> float:
        return self._sum_amounts(self.pending_effects)

    @property
    def final_amount(self) -> float:
        return self._sum_amounts(self.final_effects)

    @property
    def reserved_amount(self) -> float:
        return self._sum_amounts(self.reservation_effects)

    @property
    def consumed_amount(self) -> float:
        return self._sum_amounts(self.consumption_effects)

    @property
    def released_amount(self) -> float:
        return self._sum_amounts(self.release_effects)

    def to_dict(self) -> dict[str, Any]:
        return {
            "budget_id": self.budget_id,
            "effects": [effect.to_dict() for effect in self.effects],
            "pending_amount": self.pending_amount,
            "final_amount": self.final_amount,
            "reserved_amount": self.reserved_amount,
            "consumed_amount": self.consumed_amount,
            "released_amount": self.released_amount,
        }


@dataclass
class DecisionResult:
    outcome: DecisionOutcome
    policy_satisfied: bool
    violations: list[str] = field(default_factory=list)
    obligations: list[Obligation] = field(default_factory=list)
    recommended_action: str | None = None
    approval_state: ApprovalState = ApprovalState.NOT_REQUIRED
    approval_metadata: ApprovalMetadata | None = None
    budget_effects: list[BudgetEffect] = field(default_factory=list)
    authority_version: int = 1
    session_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "policy_satisfied": self.policy_satisfied,
            "violations": list(self.violations),
            "obligations": [item.to_dict() for item in self.obligations],
            "recommended_action": self.recommended_action,
            "approval_state": self.approval_state.value,
            "approval_metadata": (
                self.approval_metadata.to_dict() if self.approval_metadata else None
            ),
            "budget_effects": [item.to_dict() for item in self.budget_effects],
            "authority_version": self.authority_version,
            "session_id": self.session_id,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> DecisionResult:
        return cls(
            outcome=DecisionOutcome(str(raw["outcome"])),
            policy_satisfied=bool(raw["policy_satisfied"]),
            violations=[str(item) for item in raw.get("violations", [])],
            obligations=[
                Obligation.from_value(item) for item in raw.get("obligations", [])
            ],
            recommended_action=raw.get("recommended_action"),
            approval_state=ApprovalState(str(raw.get("approval_state", "not_required"))),
            approval_metadata=ApprovalMetadata.from_dict(raw.get("approval_metadata")),
            budget_effects=[
                BudgetEffect.from_value(item) for item in raw.get("budget_effects", [])
            ],
            authority_version=int(raw.get("authority_version", 1)),
            session_id=raw.get("session_id"),
        )

    def requires_approval(self) -> bool:
        return self.outcome == DecisionOutcome.PENDING_APPROVAL or self.approval_state in {
            ApprovalState.REQUIRED,
            ApprovalState.PENDING,
        }

    def requires_step_up(self) -> bool:
        return self.outcome == DecisionOutcome.PENDING_STEP_UP

    def requires_review(self) -> bool:
        return self.outcome == DecisionOutcome.ALLOW_WITH_REVIEW

    def requires_budget_reservation(self) -> bool:
        return self.outcome == DecisionOutcome.BUDGET_RESERVATION_REQUIRED

    def budget_effects_for(self, budget_id: str) -> list[BudgetEffect]:
        return [effect for effect in self.budget_effects if effect.budget_id == budget_id]

    def pending_budget_effects(self) -> list[BudgetEffect]:
        return [effect for effect in self.budget_effects if effect.is_pending()]

    def final_budget_effects(self) -> list[BudgetEffect]:
        return [effect for effect in self.budget_effects if effect.is_final()]

    def reservation_budget_effects(self) -> list[BudgetEffect]:
        return [effect for effect in self.budget_effects if effect.is_reservation()]

    def summarize_budget_effects(self) -> dict[str, BudgetEffectSummary]:
        summaries: dict[str, BudgetEffectSummary] = {}
        for effect in self.budget_effects:
            summary = summaries.setdefault(
                effect.budget_id,
                BudgetEffectSummary(budget_id=effect.budget_id),
            )
            summary.effects.append(effect)
        return summaries

    def budget_summary_dict(self) -> dict[str, dict[str, Any]]:
        return {
            budget_id: summary.to_dict()
            for budget_id, summary in self.summarize_budget_effects().items()
        }

    def budget_section(self) -> dict[str, Any] | None:
        if not self.budget_effects:
            return None
        return {
            "effects": [effect.to_dict() for effect in self.budget_effects],
            "summary": self.budget_summary_dict(),
        }

    def blocking_obligations(self) -> list[Obligation]:
        return [
            obligation
            for obligation in self.obligations
            if obligation.blocks_before_effect()
        ]

    def pending_obligations(self) -> list[Obligation]:
        return [obligation for obligation in self.obligations if obligation.is_pending()]

    def after_effect_obligations(self) -> list[Obligation]:
        return [
            obligation
            for obligation in self.obligations
            if obligation.requires_after_effect_follow_up()
        ]

    def obligation_summary(self) -> ObligationSummary:
        return ObligationSummary(obligations=list(self.obligations))

    def obligation_section(self) -> dict[str, Any] | None:
        if not self.obligations:
            return None
        return self.obligation_summary().to_dict()

    def can_execute(self) -> bool:
        if not self.policy_satisfied:
            return False
        if self.outcome not in {
            DecisionOutcome.ALLOW,
            DecisionOutcome.ALLOW_WITH_OBLIGATIONS,
            DecisionOutcome.ALLOW_WITH_REVIEW,
        }:
            return False
        if self.requires_approval() or self.requires_step_up():
            return False
        if self.requires_budget_reservation():
            return False
        return len(self.blocking_obligations()) == 0
