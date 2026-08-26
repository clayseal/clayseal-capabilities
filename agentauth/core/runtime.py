from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agentauth.core.resource_refs import ResourceRef, parse_resource_ref


class SideEffectLevel(str, Enum):
    READ_ONLY = "read_only"
    BOUNDED_WRITE = "bounded_write"
    EXTERNAL_SIDE_EFFECT = "external_side_effect"
    PRIVILEGED_MUTATION = "privileged_mutation"


class ActorKind(str, Enum):
    TOP_LEVEL_AGENT = "top_level_agent"
    AUTHORITY_BEARING_SUBAGENT = "authority_bearing_subagent"
    TOOL_PROXY = "tool_proxy"
    HUMAN_APPROVER = "human_approver"


@dataclass
class ActorRef:
    kind: ActorKind
    actor_id: str
    display_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "actor_id": self.actor_id,
            "display_name": self.display_name,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ActorRef:
        return cls(
            kind=ActorKind(str(raw["kind"])),
            actor_id=str(raw["actor_id"]),
            display_name=raw.get("display_name"),
        )


@dataclass
class ActionDescriptor:
    action_name: str
    action_category: str = "custom"
    resource_type: str | None = None
    resource_ref: str | None = None
    side_effect_level: SideEffectLevel = SideEffectLevel.EXTERNAL_SIDE_EFFECT

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_name": self.action_name,
            "action_category": self.action_category,
            "resource_type": self.resource_type,
            "resource_ref": self.resource_ref,
            "side_effect_level": self.side_effect_level.value,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ActionDescriptor:
        return cls(
            action_name=str(raw["action_name"]),
            action_category=str(raw.get("action_category", "custom")),
            resource_type=raw.get("resource_type"),
            resource_ref=raw.get("resource_ref"),
            side_effect_level=SideEffectLevel(
                str(raw.get("side_effect_level", SideEffectLevel.EXTERNAL_SIDE_EFFECT.value))
            ),
        )

    def parsed_resource_ref(self) -> ResourceRef | None:
        if not self.resource_ref:
            return None
        return parse_resource_ref(self.resource_ref)


@dataclass
class AuthorityContext:
    authority_id: str
    subject_id: str | None = None
    issuer: str | None = None
    tenant_id: str | None = None
    subject_type: str | None = None
    owner_ref: str | None = None
    workload_principal: str | None = None
    authority_version: int = 1
    session_id: str | None = None
    prior_action_count: int = 0
    capabilities: list[str] = field(default_factory=list)
    scope_claims: list[str] = field(default_factory=list)
    capability_rules: list[dict[str, Any]] = field(default_factory=list)
    selectors: list[str] = field(default_factory=list)
    attestation_type: str | None = None
    delegation_chain: list[str] = field(default_factory=list)
    expires_at: str | None = None
    lease_query_id: str | None = None
    lease_remaining_calls: int | None = None
    permit_epoch: int = 0
    trust_tier: str | None = None
    proof_of_possession: bool | None = None
    presenter_key_hash: str | None = None
    has_capability_grant: bool | None = None
    actor_ref: ActorRef | None = None
    parent_actor_ref: ActorRef | None = None
    resource_scope: list[str] = field(default_factory=list)
    budget_refs: list[str] = field(default_factory=list)
    approval_refs: list[str] = field(default_factory=list)
    evidence_verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "authority_id": self.authority_id,
            "subject_id": self.subject_id,
            "issuer": self.issuer,
            "tenant_id": self.tenant_id,
            "subject_type": self.subject_type,
            "owner_ref": self.owner_ref,
            "workload_principal": self.workload_principal,
            "authority_version": self.authority_version,
            "session_id": self.session_id,
            "prior_action_count": self.prior_action_count,
            "capabilities": list(self.capabilities),
            "scope_claims": list(self.scope_claims),
            "capability_rules": list(self.capability_rules),
            "selectors": list(self.selectors),
            "attestation_type": self.attestation_type,
            "delegation_chain": list(self.delegation_chain),
            "expires_at": self.expires_at,
            "lease_query_id": self.lease_query_id,
            "lease_remaining_calls": self.lease_remaining_calls,
            "permit_epoch": int(self.permit_epoch),
            "trust_tier": self.trust_tier,
            "proof_of_possession": self.proof_of_possession,
            "presenter_key_hash": self.presenter_key_hash,
            "has_capability_grant": self.has_capability_grant,
            "actor_ref": self.actor_ref.to_dict() if self.actor_ref else None,
            "parent_actor_ref": self.parent_actor_ref.to_dict() if self.parent_actor_ref else None,
            "resource_scope": list(self.resource_scope),
            "budget_refs": list(self.budget_refs),
            "approval_refs": list(self.approval_refs),
            "evidence_verified": self.evidence_verified,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> AuthorityContext:
        actor_ref = raw.get("actor_ref")
        parent_actor_ref = raw.get("parent_actor_ref")
        return cls(
            authority_id=str(raw["authority_id"]),
            subject_id=raw.get("subject_id"),
            issuer=raw.get("issuer"),
            tenant_id=raw.get("tenant_id", raw.get("customer_id")),
            subject_type=raw.get("subject_type", raw.get("agent_type")),
            owner_ref=raw.get("owner_ref", raw.get("owner")),
            workload_principal=raw.get("workload_principal", raw.get("spiffe_id")),
            authority_version=int(raw.get("authority_version", 1)),
            session_id=raw.get("session_id"),
            prior_action_count=int(raw.get("prior_action_count", 0)),
            capabilities=[str(item) for item in raw.get("capabilities", [])],
            scope_claims=[
                str(item) for item in raw.get("scope_claims", raw.get("scope_strings", []))
            ],
            capability_rules=[
                dict(item)
                for item in raw.get(
                    "capability_rules",
                    raw.get("capability_descriptors", []),
                )
                if isinstance(item, dict)
            ],
            selectors=[str(item) for item in raw.get("selectors", [])],
            attestation_type=raw.get("attestation_type"),
            delegation_chain=[str(item) for item in raw.get("delegation_chain", [])],
            expires_at=raw.get("expires_at"),
            lease_query_id=raw.get("lease_query_id"),
            lease_remaining_calls=(
                int(raw["lease_remaining_calls"])
                if raw.get("lease_remaining_calls") is not None
                else None
            ),
            permit_epoch=int(raw.get("permit_epoch", 0)),
            trust_tier=raw.get("trust_tier"),
            proof_of_possession=raw.get("proof_of_possession"),
            presenter_key_hash=raw.get(
                "presenter_key_hash",
                raw.get("bound_keyhash"),
            ),
            has_capability_grant=raw.get(
                "has_capability_grant",
                raw.get("has_capability_token"),
            ),
            actor_ref=ActorRef.from_dict(actor_ref) if isinstance(actor_ref, dict) else None,
            parent_actor_ref=(
                ActorRef.from_dict(parent_actor_ref) if isinstance(parent_actor_ref, dict) else None
            ),
            resource_scope=[str(item) for item in raw.get("resource_scope", [])],
            budget_refs=[str(item) for item in raw.get("budget_refs", [])],
            approval_refs=[str(item) for item in raw.get("approval_refs", [])],
            evidence_verified=bool(raw.get("evidence_verified", False)),
        )


@dataclass
class ExecutionContext:
    action: ActionDescriptor
    input: dict[str, Any]
    authority: AuthorityContext
    query_id: str | None = None
    authorization: dict[str, Any] | None = None
    touched_resources: list[str] = field(default_factory=list)
    monitoring: dict[str, Any] | None = None
    sandboxing: dict[str, Any] | None = None
    output: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "action": self.action.to_dict(),
            "input": self.input,
            "authority": self.authority.to_dict(),
            "authorization": self.authorization,
            "touched_resources": list(self.touched_resources),
        }
        if self.query_id is not None:
            out["query_id"] = self.query_id
        if self.monitoring is not None:
            out["monitoring"] = self.monitoring
        if self.sandboxing is not None:
            out["sandboxing"] = self.sandboxing
        if self.output is not None:
            out["output"] = self.output
        return out

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ExecutionContext:
        return cls(
            action=ActionDescriptor.from_dict(raw["action"]),
            input=dict(raw.get("input", {})),
            authority=AuthorityContext.from_dict(raw["authority"]),
            query_id=raw.get("query_id"),
            authorization=(
                dict(raw["authorization"]) if isinstance(raw.get("authorization"), dict) else None
            ),
            touched_resources=[str(item) for item in raw.get("touched_resources", [])],
            monitoring=(
                dict(raw["monitoring"])
                if isinstance(raw.get("monitoring"), dict)
                else None
            ),
            sandboxing=(
                dict(raw["sandboxing"])
                if isinstance(raw.get("sandboxing"), dict)
                else None
            ),
            output=dict(raw["output"]) if isinstance(raw.get("output"), dict) else None,
        )
