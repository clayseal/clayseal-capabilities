"""GCP service account / workload identity federation provider adapter.


This is a CLAIM-MAPPING adapter: it maps an already-verified token's claims onto
an `IdentitySession` and verifies nothing itself. The caller must have checked
the signature, the audience and the expiry before calling it. Pass
`evidence_verified=True` only when that is true — the verifying adapters
(`oidc_discovery`, `spiffe_workload`, `entra_agent_id`) are the ones that do the
checking themselves.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from clayseal.core.authority_binding import AuthorityBinding
from clayseal.core.identity_protocol import CapabilityAuthorizer, IdentitySession


def claims_from_gcp(raw: dict[str, Any]) -> dict[str, Any]:
    scope = raw.get("scope")
    scopes = scope.split() if isinstance(scope, str) else list(raw.get("scopes", []))
    subject = raw.get("sub") or raw.get("email") or raw.get("google.subject")
    return {
        "sub": subject,
        "iss": raw.get("iss") or "https://accounts.google.com",
        "scopes": scopes,
        "tenant_id": raw.get("project_id") or raw.get("aud"),
        "owner_ref": raw.get("email") or raw.get("service_account_email"),
        "subject_type": raw.get("subject_type") or "gcp_service_account",
        "expires_at": raw.get("exp"),
    }


@dataclass
class GcpIdentityProvider:
    name: str = "gcp_service_account"

    def to_binding(self, raw: dict[str, Any], *, evidence_verified: bool = False) -> AuthorityBinding:
        normalized = claims_from_gcp(raw)
        return AuthorityBinding.from_verified_credential(
            normalized,
            attestation_type="gcp_service_account",
            issuer=str(normalized.get("iss") or "gcp"),
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


provider = GcpIdentityProvider()
