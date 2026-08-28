"""A sub-agent may be given a subset of what its parent holds. Never more.

An agent that spawns a helper hands it authority, and the question this answers
is what stops the helper from having more than the parent. A `DelegationToken` is
signed by the parent and names capabilities; `verify_delegation_chain` walks the
chain to a trusted root and refuses any link that widens.

Attenuation is checked at every hop rather than once at the end. A chain that
narrows then widens is a chain that widens, and verifying only the endpoints
would accept exactly the case worth refusing.

Signature verification is separate from envelope verification on purpose:
`verify_delegation_signature` answers "was this signed by the key it names" and
`verify_delegation_envelope` answers "and is that key one we trust". Collapsing
them makes it easy to write code that checks the first and believes it has
checked the second.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from clayseal.core.hash_util import hash_canonical_json
from clayseal.core.operations import (
    capability_allows,
    capability_subset,
    operation_for_action,
    operation_for_mcp_tool,
)
from clayseal.core.runtime import ActionDescriptor
from clayseal.core.signing import SigningKey, verify

from .timestamps import parse_iso8601

DELEGATION_SCHEMA = "agent-receipts.delegation.v1"


@dataclass
class DelegationToken:
    """
    Cryptographically describable delegation link.

    Use ``sign_delegation()`` to produce a signed envelope before relying on the
    token in non-shadow operating modes. Child delegations reference the parent
    by ``parent_commitment`` and ship the parent's signed envelope alongside.
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

    def to_signing_dict(self) -> dict[str, Any]:
        """Canonical dict signed into a delegation envelope (no nested parent claims)."""
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
            "parent_commitment": self.parent.commitment() if self.parent else None,
        }

    def to_dict(self) -> dict[str, Any]:
        """Backward-compatible view; prefer ``to_signing_dict()`` for signatures."""
        return self.to_signing_dict()

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> DelegationToken:
        parent_raw = raw.get("parent")
        parent_commitment = raw.get("parent_commitment")
        parent = None
        if isinstance(parent_raw, dict):
            parent = cls.from_dict(parent_raw)
        elif parent_commitment is not None:
            # Parent body is carried in parent_envelope, not embedded here.
            pass
        return cls(
            delegation_id=UUID(str(raw["delegation_id"])),
            delegate_agent_id=UUID(str(raw["delegate_agent_id"])),
            capabilities=_capabilities_from_raw(raw),
            depth=int(raw.get("depth", 0)),
            issued_at=parse_iso8601(raw["issued_at"]),
            expires_at=parse_iso8601(raw["expires_at"]),
            parent=parent,
            principal_id=raw.get("principal_id"),
            organization=raw.get("organization"),
        )

    def commitment(self) -> str:
        return hash_canonical_json(self.to_signing_dict())

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
    parent_envelope: dict[str, Any] | None = None,
) -> DelegationToken:
    """Issue a child delegation with monotonically reduced capabilities."""
    if parent_envelope is not None:
        parent_violations = verify_delegation_envelope(parent_envelope, verify_chain=True)
        if parent_violations:
            raise ValueError(parent_violations[0])
        parent = delegation_from_envelope(parent_envelope)

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


def sign_delegation(
    token: DelegationToken,
    key: SigningKey,
    *,
    parent_envelope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Sign a delegation token for offline verification."""
    if token.parent is not None and parent_envelope is None:
        raise ValueError("parent_envelope is required when signing a child delegation")
    if parent_envelope is not None:
        parent_violations = verify_delegation_envelope(parent_envelope, verify_chain=True)
        if parent_violations:
            raise ValueError(parent_violations[0])
        parent_token = delegation_from_envelope(parent_envelope)
        if parent_token.commitment() != token.parent.commitment():
            raise ValueError("parent_envelope does not match delegation parent_commitment")

    document = token.to_signing_dict()
    envelope: dict[str, Any] = {"document": document, "signature": key.sign(document)}
    if parent_envelope is not None:
        envelope["parent_envelope"] = parent_envelope
    return envelope


def verify_delegation_signature(envelope: dict[str, Any]) -> bool:
    document = envelope.get("document")
    signature = envelope.get("signature")
    if not isinstance(document, dict) or not isinstance(signature, dict):
        return False
    return verify(document, signature)


def verify_delegation_envelope(
    envelope: dict[str, Any],
    *,
    verify_chain: bool = True,
) -> list[str]:
    """Return violations for a signed delegation envelope (empty if valid)."""
    document = envelope.get("document")
    if not isinstance(document, dict):
        return ["delegation document missing or invalid"]

    violations: list[str] = []
    if document.get("schema") != DELEGATION_SCHEMA:
        violations.append(f"unsupported delegation schema: {document.get('schema')!r}")
    if document.get("parent") is not None:
        violations.append(
            "signed delegation must not embed a nested parent dict; use parent_commitment + parent_envelope"
        )
    if not verify_delegation_signature(envelope):
        violations.append("delegation signature invalid")

    if not verify_chain or violations:
        return violations

    parent_commitment = document.get("parent_commitment")
    parent_envelope = envelope.get("parent_envelope")
    if parent_commitment is not None:
        if parent_envelope is None:
            violations.append("delegation missing signed parent_envelope")
            return violations
        parent_violations = verify_delegation_envelope(parent_envelope, verify_chain=True)
        violations.extend(parent_violations)
        if parent_violations:
            return violations
        try:
            parent_token = delegation_from_envelope(parent_envelope)
        except (KeyError, TypeError, ValueError) as exc:
            violations.append(f"parent delegation envelope invalid: {exc}")
            return violations
        if parent_token.commitment() != parent_commitment:
            violations.append("parent_commitment does not match signed parent_envelope")
    elif parent_envelope is not None:
        violations.append("parent_envelope present without parent_commitment")

    return violations


def delegation_from_envelope(envelope: dict[str, Any]) -> DelegationToken:
    document = envelope["document"]
    if not isinstance(document, dict):
        raise TypeError("delegation envelope document must be a dict")
    token = DelegationToken.from_dict(document)
    parent_envelope = envelope.get("parent_envelope")
    if parent_envelope is not None:
        token = DelegationToken(
            delegation_id=token.delegation_id,
            delegate_agent_id=token.delegate_agent_id,
            capabilities=token.capabilities,
            depth=token.depth,
            issued_at=token.issued_at,
            expires_at=token.expires_at,
            parent=delegation_from_envelope(parent_envelope),
            principal_id=token.principal_id,
            organization=token.organization,
        )
    return token


def verify_delegation_chain(
    token: DelegationToken | None,
    *,
    action: ActionDescriptor | None = None,
    policy: Any | None = None,
    certificate: Any | None = None,
    tool_name: str | None = None,
    signed_envelope: dict[str, Any] | None = None,
    require_signature: bool = True,
    require_token: bool = True,
) -> list[str]:
    """Return policy violations for a delegation chain (empty if valid).

    An ABSENT token is a violation by default. It used to return no violations,
    which made presenting nothing the attacker's best move against any caller
    using this as an authorization gate: a sub-agent that simply omitted its
    credential passed. A delegation benchmark scored the shipped primitive at
    0.0% containment for exactly this reason, because containment is measured at
    the attacker's best presentation and the best presentation was silence.

    `require_token=False` restores the old reading for a caller that genuinely
    treats a missing token as "this action is not delegated", which has to be an
    explicit choice rather than the default.
    """
    if token is None:
        return ([] if not require_token
                else ["no delegation token presented"])

    violations: list[str] = []
    if require_signature:
        if signed_envelope is None:
            violations.append("delegation token is not cryptographically signed")
        else:
            violations.extend(verify_delegation_envelope(signed_envelope, verify_chain=True))
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

    # Walk parent chain, scope must only shrink (parent bodies come from verified envelopes).
    current = token
    while current.parent is not None:
        violations.extend(
            capability_subset(current.capabilities, current.parent.capabilities, "chain")
        )
        current = current.parent

    return violations
