"""Azure AD / workload identity provider adapter."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentauth.core.authority_binding import AuthorityBinding
from agentauth.core.identity_protocol import CapabilityAuthorizer, IdentitySession


def claims_from_azure(raw: dict[str, Any]) -> dict[str, Any]:
    scope = raw.get("scp") or raw.get("scope")
    scopes = scope.split() if isinstance(scope, str) else list(raw.get("scopes", []))
    roles = [str(role) for role in raw.get("roles", [])]
    subject = raw.get("oid") or raw.get("sub") or raw.get("appid") or raw.get("azp")
    return {
        "sub": subject,
        "iss": raw.get("iss"),
        "scopes": scopes + roles,
        "tenant_id": raw.get("tid") or raw.get("tenant_id"),
        "owner_ref": raw.get("preferred_username") or raw.get("upn") or raw.get("appid"),
        "subject_type": raw.get("idtyp") or raw.get("agent_type") or "azure_workload",
        "expires_at": raw.get("exp"),
    }


@dataclass
class AzureAdIdentityProvider:
    name: str = "azure_ad"

    def to_binding(self, raw: dict[str, Any], *, evidence_verified: bool = False) -> AuthorityBinding:
        normalized = claims_from_azure(raw)
        return AuthorityBinding.from_verified_credential(
            normalized,
            attestation_type="azure_ad",
            issuer=str(normalized.get("iss") or "azure_ad"),
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


provider = AzureAdIdentityProvider()
