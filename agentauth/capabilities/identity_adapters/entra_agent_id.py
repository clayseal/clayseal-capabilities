"""Microsoft Entra Agent ID adapter: accept Entra-issued AGENT tokens.

Entra Agent ID (GA 2026) issues tokens for agent identities — special service
principals created from an "agent identity blueprint". The documented agent
markers are the **facet claims**:

- ``xms_act_fct`` / ``xms_sub_fct`` — value ``11`` = AgentIdentity,
  ``13`` = the agent's user account. THESE gate "is this caller an agent".
- ``xms_par_app_azp`` — the parent blueprint's app id. Microsoft explicitly
  advises against authorization decisions on it; we record it for
  attribution/audit only (it lands in ``selectors``).

Usage (needs the ``[oidc]`` extra for live verification)::

    provider = EntraAgentIdProvider(
        tenant="72f988bf-...",              # Entra tenant (GUID or domain)
        audience="api://my-resource",
        require_agent=True,                  # reject non-agent principals
    )
    session = provider.verify_session(raw_entra_jwt)
"""

from __future__ import annotations

from typing import Any

from agentauth.capabilities.identity_adapters.oidc_discovery import VerifyingOidcProvider
from agentauth.core.authority_binding import AuthorityBinding

AGENT_FACET_VALUES = {"11", "13"}  # 11 = AgentIdentity, 13 = agent user account


def _facets(claims: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for claim in ("xms_act_fct", "xms_sub_fct"):
        raw = claims.get(claim)
        if raw is None:
            continue
        items = raw if isinstance(raw, (list, tuple)) else [raw]
        values.update(str(item) for item in items)
    return values


def is_agent_token(claims: dict[str, Any]) -> bool:
    """True when the token's facet claims mark the caller as an Entra agent."""
    return bool(_facets(claims) & AGENT_FACET_VALUES)


class EntraAgentIdProvider(VerifyingOidcProvider):
    """VerifyingOidcProvider specialized for Entra Agent ID tokens."""

    def __init__(
        self,
        *,
        tenant: str | None = None,
        discovery_url: str | None = None,
        audience: str | None = None,
        require_agent: bool = True,
        **kwargs: Any,
    ) -> None:
        if discovery_url is None and tenant is not None:
            discovery_url = (
                f"https://login.microsoftonline.com/{tenant}/v2.0/"
                ".well-known/openid-configuration"
            )
        # Entra issues RS256 only.
        kwargs.setdefault("allowed_algs", ("RS256",))
        kwargs.setdefault("name", "entra_agent_id")
        super().__init__(discovery_url=discovery_url, audience=audience, **kwargs)
        self.require_agent = require_agent

    def to_binding(
        self, raw: dict[str, Any] | str, *, evidence_verified: bool = False
    ) -> AuthorityBinding:
        if isinstance(raw, str):
            claims = self.verify(raw)
            evidence_verified = True
        else:
            claims = raw

        if self.require_agent and not is_agent_token(claims):
            raise ValueError(
                "token is not an Entra AGENT identity (xms_act_fct/xms_sub_fct "
                "facets 11/13 absent); pass require_agent=False to accept any principal"
            )

        normalized = dict(claims)
        # Prefer the immutable object id over sub for a stable subject.
        normalized.setdefault("subject_id", claims.get("oid") or claims.get("sub"))
        normalized.setdefault("tenant_id", claims.get("tid"))
        binding = AuthorityBinding.from_verified_credential(
            normalized,
            attestation_type="entra_agent_id",
            issuer=str(claims.get("iss") or self._issuer or "unknown"),
            evidence_verified=evidence_verified,
        )
        # Attribution only — never authorize on the parent blueprint id.
        blueprint = claims.get("xms_par_app_azp")
        if blueprint:
            binding.selectors.append(f"entra:blueprint:{blueprint}")
        for facet in sorted(_facets(claims)):
            binding.selectors.append(f"entra:facet:{facet}")
        return binding
