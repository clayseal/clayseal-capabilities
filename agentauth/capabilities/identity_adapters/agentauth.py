"""AgentAuth native identity (reference provider)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentauth.core.authority_binding import AuthorityBinding
from agentauth.core.identity_protocol import CapabilityAuthorizer, IdentitySession


@dataclass
class AgentAuthIdentityProvider:
    name: str = "agentauth"

    def to_binding(self, raw: dict[str, Any], *, evidence_verified: bool = True) -> AuthorityBinding:
        binding = AuthorityBinding.from_agentauth_credential(raw)
        binding.evidence_verified = evidence_verified
        return binding

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


provider = AgentAuthIdentityProvider()
