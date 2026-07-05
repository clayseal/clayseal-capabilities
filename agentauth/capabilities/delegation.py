from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from agentauth.capabilities.operations import (
    capability_allows,
    capability_subset,
    operation_for_action,
    operation_for_mcp_tool,
)
from agentauth.core.hash_util import hash_canonical_json
from agentauth.core.runtime import ActionDescriptor
from agentauth.core.signing import SigningKey, verify

DELEGATION_SCHEMA = "agent-receipts.delegation.v1"


@dataclass
class DelegationToken:
    """
    Cryptographically describable delegation link.

    Use ``sign_delegation()`` to produce a signed envelope before relying on the
    token in non-shadow operating modes.
    """

    delegation_id: UUID
    delegate_agent_id: UUID
    capabilities: list[dict[str, str]]
    depth: int
    issued_at: datetime
    expires_at: datetime
    parent: DelegationToken | None = None
    principal_id: str | None = None
    organization: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": DELEGATION_SCHEMA,
            "delegation_id": str(self.delegation_id),
            "delegate_agent_id": str(self.delegate_agent_id),
            "capabilities": list(self.capabilities),
            "depth": self.depth,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "principal_id": self.principal_id,
            "organization": self.organization,
            "parent": self.parent.to_dict() if self.parent else None,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> DelegationToken:
        parent_raw = raw.get("parent")
        parent = cls.from_dict(parent_raw) if isinstance(parent_raw, dict) else None
        return cls(
            delegation_id=UUID(str(raw["delegation_id"])),
            delegate_agent_id=UUID(str(raw["delegate_agent_id"])),
            capabilities=_capabilities_from_raw(raw),
            depth=int(raw.get("depth", 0)),
            issued_at=datetime.fromisoformat(raw["issued_at"]),
            expires_at=datetime.fromisoformat(raw["expires_at"]),
            parent=parent,
            principal_id=raw.get("principal_id"),
            organization=raw.get("organization"),
        )

    def commitment(self) -> str:
        return hash_canonical_json(self.to_dict())

    def is_valid_at(self, at: datetime | None = None) -> bool:
        at = at or datetime.now(timezone.utc)
        return self.issued_at <= at < self.expires_at


def _capabilities_from_raw(raw: dict[str, Any]) -> list[dict[str, str]]:
    capabilities = raw.get("capabilities")
    if isinstance(capabilities, list):
        return [
            {"resource": str(item.get("resource")), "action": str(item.get("action"))}
            for item in capabilities
            if isinstance(item, dict) and item.get("resource") and item.get("action")
        ]
    return []


def issue_delegation(
    parent: DelegationToken | None,
    *,
    delegate_agent_id: UUID,
    capabilities: list[dict[str, Any]],
    certificate: Any | None = None,
    policy: Any | None = None,
    ttl_seconds: int = 3600,
    principal_id: str | None = None,
    organization: str | None = None,
) -> DelegationToken:
    """Issue a child delegation with monotonically reduced capabilities."""
    now = datetime.now(timezone.utc)
    depth = 0 if parent is None else parent.depth + 1

    if parent is not None:
        violations = capability_subset(capabilities, parent.capabilities, "delegation")
        if violations:
            raise ValueError(violations[0])

    return DelegationToken(
        delegation_id=uuid4(),
        delegate_agent_id=delegate_agent_id,
        capabilities=sorted(
            (
                {"resource": str(cap["resource"]), "action": str(cap["action"])}
                for cap in capabilities
                if cap.get("resource") and cap.get("action")
            ),
            key=lambda cap: (cap["resource"], cap["action"]),
        ),
        depth=depth,
        issued_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
        parent=parent,
        principal_id=principal_id or (certificate.principal.principal_id if certificate else None),
        organization=organization or (certificate.principal.organization if certificate else None),
    )


def sign_delegation(token: DelegationToken, key: SigningKey) -> dict[str, Any]:
    """Sign a delegation token for offline verification."""
    document = token.to_dict()
    return {"document": document, "signature": key.sign(document)}


def verify_delegation_signature(envelope: dict[str, Any]) -> bool:
    document = envelope.get("document")
    signature = envelope.get("signature")
    if not isinstance(document, dict) or not isinstance(signature, dict):
        return False
    return verify(document, signature)


def verify_delegation_envelope(envelope: dict[str, Any]) -> list[str]:
    """Return violations for a signed delegation envelope (empty if valid)."""
    document = envelope.get("document")
    if not isinstance(document, dict):
        return ["delegation document missing or invalid"]

    violations: list[str] = []
    if document.get("schema") != DELEGATION_SCHEMA:
        violations.append(f"unsupported delegation schema: {document.get('schema')!r}")
    if not verify_delegation_signature(envelope):
        violations.append("delegation signature invalid")
    return violations


def delegation_from_envelope(envelope: dict[str, Any]) -> DelegationToken:
    document = envelope["document"]
    if not isinstance(document, dict):
        raise TypeError("delegation envelope document must be a dict")
    return DelegationToken.from_dict(document)


def verify_delegation_chain(
    token: DelegationToken | None,
    *,
    action: ActionDescriptor | None = None,
    policy: Any | None = None,
    certificate: Any | None = None,
    tool_name: str | None = None,
    signed_envelope: dict[str, Any] | None = None,
    require_signature: bool = False,
) -> list[str]:
    """Return policy violations for a delegation chain (empty if valid)."""
    if token is None:
        return []

    violations: list[str] = []
    if require_signature:
        if signed_envelope is None:
            violations.append("delegation token is not cryptographically signed")
        else:
            violations.extend(verify_delegation_envelope(signed_envelope))
            if not violations:
                try:
                    signed_token = delegation_from_envelope(signed_envelope)
                except (KeyError, TypeError, ValueError) as exc:
                    violations.append(f"signed delegation document invalid: {exc}")
                else:
                    if signed_token.commitment() != token.commitment():
                        violations.append(
                            "signed delegation does not match delegation token"
                        )

    if not token.is_valid_at():
        violations.append("delegation token expired or not yet valid")

    operation = None
    if action is not None:
        operation = operation_for_action(action)
    elif tool_name is not None:
        operation = operation_for_mcp_tool(tool_name)

    if operation is not None and not capability_allows(
        token.capabilities,
        operation.resource,
        operation.action,
    ):
        violations.append(f"delegation capabilities do not allow {operation.label()}")

    # Walk parent chain — scope must only shrink
    current = token
    while current.parent is not None:
        violations.extend(
            capability_subset(current.capabilities, current.parent.capabilities, "chain")
        )
        current = current.parent

    return violations
