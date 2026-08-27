"""Pluggable L1 identity provider adapters.

Claim-mapping adapters (trust the caller's verification): ``agentauth``,
``spiffe_jwt``, ``oidc``, ``auth0``, ``aws_sts``. Because these do NOT verify
the credential themselves, ``spiffe_jwt``/``oidc``/``auth0``/``aws_sts`` default
``evidence_verified=False``, a caller that has already verified the credential
out-of-band must opt in explicitly. Verifying adapters (do the
cryptography themselves): ``VerifyingOidcProvider`` (any OIDC discovery/JWKS
issuer, ``[oidc]`` extra), ``EntraAgentIdProvider`` (Entra Agent ID tokens,
facet-claim gated, ``[oidc]``), ``A2AAgentCardProvider`` (A2A signed
AgentCards, ``[a2a]``). Live-fetch: ``SpiffeWorkloadProvider`` pulls fresh
JWT-SVIDs from a SPIFFE agent's Workload API (``[spiffe]``).

Third parties add providers via the ``agentauth.identity_providers``
entry-point group or ``register_identity_provider``, see
``clayseal.core.plugins``.
"""
from __future__ import annotations

from clayseal.capabilities.identity_adapters.a2a_agentcard import (
    A2AAgentCardProvider,
    verify_agent_card,
)
from clayseal.capabilities.identity_adapters.entra_agent_id import (
    EntraAgentIdProvider,
    is_agent_token,
)
from clayseal.capabilities.identity_adapters.oidc_discovery import VerifyingOidcProvider
from clayseal.capabilities.identity_adapters.registry import (
    get_identity_provider,
    list_identity_providers,
    register_identity_provider,
)
from clayseal.capabilities.identity_adapters.spiffe_workload import SpiffeWorkloadProvider

__all__ = [
    "A2AAgentCardProvider",
    "EntraAgentIdProvider",
    "SpiffeWorkloadProvider",
    "VerifyingOidcProvider",
    "get_identity_provider",
    "is_agent_token",
    "list_identity_providers",
    "register_identity_provider",
    "verify_agent_card",
]
