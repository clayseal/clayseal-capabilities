"""Generic OIDC / OAuth2 workload access tokens."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentauth.core.authority_binding import AuthorityBinding
from agentauth.core.identity_protocol import CapabilityAuthorizer, IdentitySession


def claims_from_oidc(claims: dict[str, Any]) -> dict[str, Any]:
    scope = claims.get("scope", "")
    scopes = scope.split() if isinstance(scope, str) else list(claims.get("scopes", []))
    return {
        "sub": claims.get("sub"),
        "iss": claims.get("iss"),
        "scopes": scopes,
        "tenant_id": claims.get("tenant") or claims.get("tid") or claims.get("org_id"),
        "owner_ref": claims.get("email") or claims.get("preferred_username"),
        "expires_at": claims.get("exp"),
        "subject_type": claims.get("role") or claims.get("agent_type"),
    }


@dataclass
class OidcIdentityProvider:
    name: str = "oidc"

    def to_binding(self, raw: dict[str, Any], *, evidence_verified: bool = True) -> AuthorityBinding:
        normalized = claims_from_oidc(raw) if "sub" in raw and "iss" in raw else raw
        return AuthorityBinding.from_verified_credential(
            normalized,
            attestation_type="oidc",
            issuer=str(normalized.get("iss", "oidc")),
            evidence_verified=evidence_verified,
        )

    def build_session(
        self,
        raw: dict[str, Any],
        *,
        capability_authorizer: CapabilityAuthorizer | None = None,
        evidence_verified: bool = True,
    ) -> IdentitySession:
        return IdentitySession(
            binding=self.to_binding(raw, evidence_verified=evidence_verified),
            provider=self.name,
            capability_authorizer=capability_authorizer,
            raw_credential=raw,
        )


provider = OidcIdentityProvider()
