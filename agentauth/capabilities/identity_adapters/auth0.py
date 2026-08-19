"""Auth0 machine-to-machine / client-credentials tokens."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentauth.core.authority_binding import AuthorityBinding
from agentauth.core.identity_protocol import CapabilityAuthorizer, IdentitySession

from ._claims import strip_authority_fields


def claims_from_auth0(claims: dict[str, Any]) -> dict[str, Any]:
    scopes = claims.get("scope", "")
    if isinstance(scopes, str):
        scopes = scopes.split()
    permissions = claims.get("permissions") or []
    tenant = claims.get("org_id") or claims.get("https://auth0.com/org_id")
    return {
        "sub": claims.get("sub"),
        "iss": claims.get("iss"),
        "scopes": list(scopes) + [str(p) for p in permissions],
        "tenant_id": tenant,
        "owner_ref": claims.get("azp") or claims.get("client_id"),
        "subject_type": claims.get("gty") or "client",
        "expires_at": claims.get("exp"),
    }


@dataclass
class Auth0IdentityProvider:
    name: str = "auth0"

    def to_binding(self, raw: dict[str, Any], *, evidence_verified: bool = False) -> AuthorityBinding:
        normalized = (
            claims_from_auth0(raw)
            if "iss" in raw and "auth0.com" in str(raw.get("iss", ""))
            else strip_authority_fields(raw))
        return AuthorityBinding.from_verified_credential(
            normalized,
            attestation_type="auth0_m2m",
            issuer=str(normalized.get("iss", "auth0")),
            evidence_verified=evidence_verified,
        )

    def build_session(
        self,
        raw: dict[str, Any],
        *,
        capability_authorizer: CapabilityAuthorizer | None = None,
        evidence_verified: bool = False,
    ) -> IdentitySession:
        return IdentitySession(
            binding=self.to_binding(raw, evidence_verified=evidence_verified),
            provider=self.name,
            capability_authorizer=capability_authorizer,
            raw_credential=raw,
        )


provider = Auth0IdentityProvider()
