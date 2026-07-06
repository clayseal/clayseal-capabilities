"""AWS STS / IAM role session identity."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentauth.core.authority_binding import AuthorityBinding
from agentauth.core.identity_protocol import CapabilityAuthorizer, IdentitySession


def claims_from_aws_sts(raw: dict[str, Any]) -> dict[str, Any]:
    if "Arn" in raw:
        arn = str(raw["Arn"])
        account = str(raw.get("Account", ""))
        return {
            "sub": arn,
            "subject_id": arn,
            "tenant_id": account or None,
            "issuer": f"aws:sts:{account}" if account else "aws:sts",
            "subject_type": "iam_role",
            "scopes": list(raw.get("scopes", [])),
            "expires_at": raw.get("Expiration"),
        }
    return {
        "sub": raw.get("sub"),
        "iss": raw.get("iss"),
        "tenant_id": raw.get("account") or raw.get("aud"),
        "subject_type": "aws_web_identity",
        "scopes": (raw.get("scope", "") or "").split() if isinstance(raw.get("scope"), str) else [],
        "expires_at": raw.get("exp"),
    }


@dataclass
class AwsStsIdentityProvider:
    name: str = "aws_sts"

    def to_binding(self, raw: dict[str, Any], *, evidence_verified: bool = False) -> AuthorityBinding:
        normalized = claims_from_aws_sts(raw)
        return AuthorityBinding.from_verified_credential(
            normalized,
            attestation_type="aws_sts",
            issuer=str(normalized.get("issuer") or normalized.get("iss") or "aws:sts"),
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


provider = AwsStsIdentityProvider()
