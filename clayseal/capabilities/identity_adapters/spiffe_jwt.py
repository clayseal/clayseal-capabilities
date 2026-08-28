"""SPIFFE JWT-SVID / SPIRE workload identity.


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

from ._claims import strip_authority_fields


def claims_from_spiffe_jwt(claims: dict[str, Any]) -> dict[str, Any]:
    sub = claims.get("sub")
    if sub and not str(sub).startswith("spiffe://"):
        raise ValueError("SPIFFE JWT must use spiffe:// subject")
    scopes = claims.get("scopes") or claims.get("scope") or []
    if isinstance(scopes, str):
        scopes = scopes.split()
    return {
        "sub": sub,
        "spiffe_id": sub,
        "iss": claims.get("iss"),
        "scopes": list(scopes),
        "selectors": list(claims.get("selectors", [])),
        "expires_at": claims.get("exp"),
        "agent_type": claims.get("agent_type"),
    }


@dataclass
class SpiffeJwtIdentityProvider:
    name: str = "spiffe_jwt"

    def to_binding(self, raw: dict[str, Any], *, evidence_verified: bool = False) -> AuthorityBinding:
        normalized = (claims_from_spiffe_jwt(raw) if "sub" in raw
                      else strip_authority_fields(raw))
        return AuthorityBinding.from_verified_credential(
            normalized,
            attestation_type="spiffe_jwt",
            issuer=normalized.get("iss"),
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


provider = SpiffeJwtIdentityProvider()
