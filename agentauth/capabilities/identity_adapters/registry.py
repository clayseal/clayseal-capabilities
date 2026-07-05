"""Registry of pluggable L1 identity providers."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentauth.core.identity_protocol import IdentityProvider

_PROVIDERS: dict[str, IdentityProvider] = {}


def register_identity_provider(provider: IdentityProvider) -> None:
    _PROVIDERS[provider.name] = provider


def get_identity_provider(name: str) -> IdentityProvider:
    _ensure_loaded()
    if name not in _PROVIDERS:
        raise KeyError(f"unknown identity provider {name!r}; known: {', '.join(sorted(_PROVIDERS))}")
    return _PROVIDERS[name]


def list_identity_providers() -> list[str]:
    _ensure_loaded()
    return sorted(_PROVIDERS)


def _ensure_loaded() -> None:
    if _PROVIDERS:
        return
    from agentauth.capabilities.identity_adapters import agentauth as _a
    from agentauth.capabilities.identity_adapters import auth0 as _auth0
    from agentauth.capabilities.identity_adapters import aws_sts as _aws
    from agentauth.capabilities.identity_adapters import oidc as _oidc
    from agentauth.capabilities.identity_adapters import spiffe_jwt as _spiffe

    for mod in (_a, _spiffe, _oidc, _auth0, _aws):
        register_identity_provider(mod.provider)
