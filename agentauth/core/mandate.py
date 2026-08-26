"""Signed Mandate objects for AP2-style receipt binding (SOTA-6).

A Mandate authorizes spend limits, allowed actions/resources, and a validity window.
Receipt bundles reference the mandate by ``grant_id`` + commitment and embed the signed
document so offline verifiers can confirm the action stayed within scope.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from agentauth.core.budget import CapabilityBudget
from agentauth.core.decision import BudgetEffect, DecisionResult
from agentauth.core.hash_util import hash_canonical_json
from agentauth.core.runtime import ActionDescriptor
from agentauth.core.signing import SigningKey, verify

MANDATE_SCHEMA = "agent-receipts.mandate.v1"
REQUIRE_MANDATE_FOR_BUDGETS_ENV = "AGENT_RECEIPTS_REQUIRE_MANDATE_FOR_BUDGETS"
REQUIRE_MANDATE_ACTIONS_ENV = "AGENT_RECEIPTS_REQUIRE_MANDATE_ACTIONS"


@dataclass
class Mandate:
    """Authorizing grant: spend/scope/validity bound to a signed document."""

    grant_id: str
    issuer: str
    issued_at: datetime
    expires_at: datetime
    delegate: str | None = None
    allowed_actions: list[str] = field(default_factory=list)
    allowed_resources: list[str] = field(default_factory=list)
    budgets: list[CapabilityBudget] = field(default_factory=list)
    parent_grant_id: str | None = None
    owner_hpke_pk: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema": MANDATE_SCHEMA,
            "grant_id": self.grant_id,
            "issuer": self.issuer,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "delegate": self.delegate,
            "allowed_actions": list(self.allowed_actions),
            "allowed_resources": list(self.allowed_resources),
            "budgets": [item.to_dict() for item in self.budgets],
            "parent_grant_id": self.parent_grant_id,
        }
        if self.owner_hpke_pk:
            payload["owner_hpke_pk"] = self.owner_hpke_pk
        return payload

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Mandate:
        return cls(
            grant_id=str(raw["grant_id"]),
            issuer=str(raw["issuer"]),
            issued_at=datetime.fromisoformat(raw["issued_at"]),
            expires_at=datetime.fromisoformat(raw["expires_at"]),
            delegate=raw.get("delegate"),
            allowed_actions=[str(item) for item in raw.get("allowed_actions", [])],
            allowed_resources=[str(item) for item in raw.get("allowed_resources", [])],
            budgets=[CapabilityBudget.from_dict(item) for item in raw.get("budgets", [])],
            parent_grant_id=raw.get("parent_grant_id"),
            owner_hpke_pk=raw.get("owner_hpke_pk"),
        )

    def commitment(self) -> str:
        return hash_canonical_json(self.to_dict())

    def is_valid_at(self, at: datetime) -> bool:
        return self.issued_at <= at < self.expires_at


def issue_mandate(
    *,
    issuer: str,
    key: SigningKey,
    budgets: list[CapabilityBudget] | None = None,
    allowed_actions: list[str] | None = None,
    allowed_resources: list[str] | None = None,
    delegate: str | None = None,
    parent_grant_id: str | None = None,
    grant_id: str | None = None,
    ttl_seconds: int = 3600,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    owner_hpke_pk: str | None = None,
) -> dict[str, Any]:
    """Create and sign a mandate envelope ``{document, signature}``."""
    now = issued_at or datetime.now(timezone.utc)
    mandate = Mandate(
        grant_id=grant_id or str(uuid4()),
        issuer=issuer,
        issued_at=now,
        expires_at=expires_at or (now + timedelta(seconds=ttl_seconds)),
        delegate=delegate,
        allowed_actions=sorted(set(allowed_actions or [])),
        allowed_resources=sorted(set(allowed_resources or [])),
        budgets=list(budgets or []),
        parent_grant_id=parent_grant_id,
        owner_hpke_pk=owner_hpke_pk,
    )
    document = mandate.to_dict()
    return {"document": document, "signature": key.sign(document)}


def mandated_hpke_recipient_bytes(bundle: dict[str, Any]) -> bytes | None:
    """Decode ``owner_hpke_pk`` from an embedded mandate, if present (SOTA-16a)."""
    import base64

    def b64url_decode(value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value + padding)

    mandate = bundle.get("mandate")
    if not isinstance(mandate, dict):
        return None
    document = mandate.get("document")
    if not isinstance(document, dict):
        return None
    owner_pk = document.get("owner_hpke_pk")
    if not isinstance(owner_pk, str) or not owner_pk:
        return None
    try:
        return b64url_decode(owner_pk)
    except (ValueError, TypeError):
        return None


def mandate_reference(envelope: dict[str, Any]) -> dict[str, str]:
    """Receipt-facing reference: grant id + content commitment."""
    document = envelope["document"]
    mandate = Mandate.from_dict(document)
    return {
        "grant_id": mandate.grant_id,
        "commitment": mandate.commitment(),
    }


def mandate_bundle_section(envelope: dict[str, Any]) -> dict[str, Any]:
    """Embed a signed mandate on a receipt bundle."""
    document = envelope["document"]
    return {
        **mandate_reference(envelope),
        "document": document,
        "signature": envelope["signature"],
    }


def mandate_signer_matches_issuer(issuer: str, signature: dict[str, Any]) -> bool:
    """True when the mandate issuer is bound to the Ed25519 signer."""
    public_key = signature.get("public_key")
    if not isinstance(public_key, str) or not public_key:
        return False
    key_id = signature.get("key_id")
    normalized = issuer.removeprefix("ed25519:")
    if issuer == public_key or normalized == public_key:
        # A self-referential issuer (the issuer field merely repeats the
        # signature's own public key) is self-attestation: any keyholder could
        # mint such a mandate. Refuse it in production; the issuer must be a
        # key_id that verification anchors to a registered signer.
        from agentauth.core.production import is_production

        return not is_production()
    return isinstance(key_id, str) and issuer == key_id


def _receipt_authority_identities(bundle: dict[str, Any]) -> set[str]:
    """Collect comparable actor identities from a receipt bundle."""
    identities: set[str] = set()
    authority = bundle.get("authority")
    if isinstance(authority, dict):
        for key in (
            "subject_id",
            "authority_id",
            "workload_principal",
            "issuer",
            "owner_ref",
            "tenant_id",
        ):
            value = authority.get(key)
            if value:
                identities.add(str(value))
        actor_ref = authority.get("actor_ref")
        if isinstance(actor_ref, dict) and actor_ref.get("actor_id"):
            identities.add(str(actor_ref["actor_id"]))
        parent_actor = authority.get("parent_actor_ref")
        if isinstance(parent_actor, dict) and parent_actor.get("actor_id"):
            identities.add(str(parent_actor["actor_id"]))
        for item in authority.get("delegation_chain", []):
            if item:
                identities.add(str(item))

    certificate = bundle.get("certificate")
    if isinstance(certificate, dict):
        if certificate.get("agent_id"):
            identities.add(str(certificate["agent_id"]))
        principal = certificate.get("principal")
        if isinstance(principal, dict) and principal.get("principal_id"):
            identities.add(str(principal["principal_id"]))

    proof = bundle.get("execution_proof", {})
    if isinstance(proof, dict) and proof.get("agent_id"):
        identities.add(str(proof["agent_id"]))

    return identities


def verify_mandate_signature(envelope: dict[str, Any]) -> bool:
    """Verify the Ed25519 signature over the mandate document."""
    document = envelope.get("document")
    signature = envelope.get("signature")
    if not isinstance(document, dict) or not isinstance(signature, dict):
        return False
    return verify(document, signature)


def verify_mandate_envelope(envelope: dict[str, Any]) -> list[str]:
    """Return violations for a signed mandate envelope (empty if valid)."""
    document = envelope.get("document")
    if not isinstance(document, dict):
        return ["mandate document missing or invalid"]

    violations: list[str] = []
    if document.get("schema") != MANDATE_SCHEMA:
        violations.append(f"unsupported mandate schema: {document.get('schema')!r}")

    if not verify_mandate_signature(envelope):
        violations.append("mandate signature invalid")
        return violations

    signature = envelope.get("signature")
    issuer = str(document.get("issuer", ""))
    if not isinstance(signature, dict) or not mandate_signer_matches_issuer(issuer, signature):
        violations.append("mandate issuer is not bound to signature public_key")

    return violations


def _resource_matches(allowed: list[str], action: ActionDescriptor) -> bool:
    if not allowed:
        return True
    candidates = [
        action.resource_ref,
        action.resource_type,
        action.action_name,
    ]
    allowed_set = set(allowed)
    return any(item in allowed_set for item in candidates if item)


def _effect_spend_for_budget(
    effects: list[BudgetEffect], budget_id: str
) -> float:
    total = 0.0
    for effect in effects:
        if effect.budget_id != budget_id:
            continue
        if effect.is_consumption() or effect.is_reservation():
            if isinstance(effect.amount, (int, float)):
                total += float(effect.amount)
    return total


def check_receipt_against_mandate(
    mandate: Mandate,
    *,
    action: dict[str, Any] | ActionDescriptor,
    decision: dict[str, Any] | DecisionResult,
    at: datetime,
) -> list[str]:
    """Return violations when a receipt action/decision exceeds the mandate."""
    action_desc = (
        action
        if isinstance(action, ActionDescriptor)
        else ActionDescriptor.from_dict(action)
    )
    decision_result = (
        decision
        if isinstance(decision, DecisionResult)
        else DecisionResult.from_dict(decision)
    )

    violations: list[str] = []
    if not mandate.is_valid_at(at):
        violations.append("mandate expired or not yet valid")

    if mandate.allowed_actions and action_desc.action_name not in mandate.allowed_actions:
        violations.append(
            f"action {action_desc.action_name!r} not in mandate allowed_actions"
        )

    if not _resource_matches(mandate.allowed_resources, action_desc):
        violations.append("action resource not in mandate allowed_resources")

    for budget in mandate.budgets:
        spend = _effect_spend_for_budget(decision_result.budget_effects, budget.budget_id)
        limit = float(budget.limit)
        if spend > limit:
            violations.append(
                f"budget {budget.budget_id!r} effect {spend} exceeds mandate limit {limit}"
            )

    return violations


def _mandate_scope_subset(child: list[str], parent: list[str], label: str) -> list[str]:
    if not parent:
        return []
    parent_set = set(parent)
    extra = [item for item in child if item not in parent_set]
    if extra:
        return [f"{label} {extra} exceed parent mandate scope {parent}"]
    return []


def _mandate_budget_subset(child: Mandate, parent: Mandate) -> list[str]:
    parent_limits = {budget.budget_id: float(budget.limit) for budget in parent.budgets}
    violations: list[str] = []
    for budget in child.budgets:
        parent_limit = parent_limits.get(budget.budget_id)
        if parent_limit is None:
            violations.append(
                f"mandate budget {budget.budget_id!r} is not present on parent grant"
            )
            continue
        if float(budget.limit) > parent_limit:
            violations.append(
                f"mandate budget {budget.budget_id!r} limit {budget.limit} "
                f"exceeds parent limit {parent_limit}"
            )
    return violations


def _mandate_parent_issues(section: dict[str, Any], mandate: Mandate) -> list[str]:
    if not mandate.parent_grant_id:
        return []

    parent_section = section.get("parent")
    if not isinstance(parent_section, dict):
        return ["mandate parent_grant_id set but parent mandate not embedded"]

    parent_document = parent_section.get("document")
    parent_signature = parent_section.get("signature")
    if not isinstance(parent_document, dict) or not isinstance(parent_signature, dict):
        return ["parent mandate section missing document or signature"]

    parent_envelope = {"document": parent_document, "signature": parent_signature}
    violations = verify_mandate_envelope(parent_envelope)
    if violations:
        return [f"parent mandate invalid: {item}" for item in violations]

    parent_mandate = Mandate.from_dict(parent_document)
    if mandate.parent_grant_id != parent_mandate.grant_id:
        violations = ["mandate parent_grant_id does not match parent mandate grant_id"]
    else:
        violations = []

    if parent_mandate.delegate and mandate.issuer != parent_mandate.delegate:
        violations.append(
            "parent mandate delegate does not match child mandate issuer"
        )
    if mandate.issued_at < parent_mandate.issued_at:
        violations.append("child mandate issued_at is earlier than parent mandate")
    if mandate.expires_at > parent_mandate.expires_at:
        violations.append("child mandate expires_at exceeds parent mandate validity")

    violations.extend(
        _mandate_scope_subset(
            mandate.allowed_actions,
            parent_mandate.allowed_actions,
            "allowed_actions",
        )
    )
    violations.extend(
        _mandate_scope_subset(
            mandate.allowed_resources,
            parent_mandate.allowed_resources,
            "allowed_resources",
        )
    )
    violations.extend(_mandate_budget_subset(mandate, parent_mandate))
    return violations


def _split_env_list(name: str) -> set[str]:
    raw = os.getenv(name, "")
    return {item.strip() for item in raw.split(",") if item.strip()}


def _require_mandate_for_budgets() -> bool:
    return os.getenv(REQUIRE_MANDATE_FOR_BUDGETS_ENV, "1") != "0"


def _bundle_budget_effects(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    budget = bundle.get("budget")
    if isinstance(budget, dict):
        effects = budget.get("effects")
        if isinstance(effects, list):
            return [item for item in effects if isinstance(item, dict)]
    decision = bundle.get("decision")
    if isinstance(decision, dict):
        effects = decision.get("budget_effects")
        if isinstance(effects, list):
            return [item for item in effects if isinstance(item, dict)]
    return []


def _mandate_requirement_issues(bundle: dict[str, Any]) -> list[str]:
    action = bundle.get("action") if isinstance(bundle.get("action"), dict) else {}
    action_name = str(action.get("action_name", ""))
    required_actions = _split_env_list(REQUIRE_MANDATE_ACTIONS_ENV)

    if action_name and action_name in required_actions:
        return [f"signed mandate required for action {action_name!r}"]

    if _require_mandate_for_budgets() and _bundle_budget_effects(bundle):
        return ["signed mandate required for budget-affecting receipt"]

    return []


def verify_bundle_mandate(
    bundle: dict[str, Any],
    *,
    at: datetime | None = None,
) -> list[str]:
    """Verify mandate binding on a receipt bundle (empty if valid or absent)."""
    section = bundle.get("mandate")
    if not section:
        return _mandate_requirement_issues(bundle)

    document = section.get("document")
    signature = section.get("signature")
    if not isinstance(document, dict) or not isinstance(signature, dict):
        return ["mandate section missing document or signature"]

    envelope = {"document": document, "signature": signature}
    violations = verify_mandate_envelope(envelope)
    if violations:
        return violations

    mandate = Mandate.from_dict(document)
    if section.get("grant_id") != mandate.grant_id:
        violations.append("mandate grant_id does not match document")
    if section.get("commitment") != mandate.commitment():
        violations.append("mandate commitment does not match document")

    if mandate.delegate:
        identities = _receipt_authority_identities(bundle)
        if not identities:
            violations.append(
                "mandate delegate is set but receipt has no comparable authority identity"
            )
        elif mandate.delegate not in identities:
            violations.append(
                f"mandate delegate {mandate.delegate!r} does not match receipt authority"
            )

    violations.extend(_mandate_parent_issues(section, mandate))

    proof = bundle.get("execution_proof", {})
    action_at = at
    if action_at is None and proof.get("created_at"):
        action_at = datetime.fromisoformat(proof["created_at"])
    if action_at is None:
        action_at = datetime.now(timezone.utc)

    decision = bundle.get("decision", {})
    action = bundle.get("action", {})
    violations.extend(
        check_receipt_against_mandate(
            mandate,
            action=action,
            decision=decision,
            at=action_at,
        )
    )
    return violations
