"""Pluggable L1 identity provider adapters.

Claim-mapping adapters (trust the caller's verification): ``agentauth``,
``spiffe_jwt``, ``oidc``, ``auth0``, ``aws_sts``. Verifying adapters (do the
cryptography themselves, need the ``[oidc]`` extra):
``VerifyingOidcProvider`` (any OIDC discovery/JWKS issuer) and
``EntraAgentIdProvider`` (Entra Agent ID tokens, facet-claim gated).

Third parties add providers via the ``agentauth.identity_providers``
entry-point group or ``register_identity_provider`` — see
``agentauth.core.plugins``.
"""
from __future__ import annotations

from agentauth.capabilities.identity_adapters.entra_agent_id import (
    EntraAgentIdProvider,
    is_agent_token,
)
from agentauth.capabilities.identity_adapters.oidc_discovery import VerifyingOidcProvider
from agentauth.capabilities.identity_adapters.registry import (
    get_identity_provider,
    list_identity_providers,
    register_identity_provider,
)

__all__ = [
    "get_identity_provider",
    "list_identity_providers",
    "register_identity_provider",
    "VerifyingOidcProvider",
    "EntraAgentIdProvider",
    "is_agent_token",
]
