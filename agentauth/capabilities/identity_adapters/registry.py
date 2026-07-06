"""Registry of pluggable L1 identity providers.

Backed by the shared plugin registry (``agentauth.core.plugins``,
entry-point group ``agentauth.identity_providers``): third-party packages add
providers by declaring an entry point — no edits to this package needed. The
five built-in adapters are registered lazily on first use.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agentauth.core.plugins import get_plugin, list_plugins, register_plugin

if TYPE_CHECKING:
    from agentauth.core.identity_protocol import IdentityProvider

_GROUP = "identity_providers"
_BUILTINS_LOADED = False


def register_identity_provider(provider: IdentityProvider) -> None:
    register_plugin(_GROUP, provider.name, provider)


def get_identity_provider(name: str) -> IdentityProvider:
    _ensure_loaded()
    try:
        return get_plugin(_GROUP, name)
    except KeyError:
        known = ", ".join(list_identity_providers())
        raise KeyError(f"unknown identity provider {name!r}; known: {known}") from None


def list_identity_providers() -> list[str]:
    _ensure_loaded()
    return list_plugins(_GROUP)


def _ensure_loaded() -> None:
    global _BUILTINS_LOADED
    if _BUILTINS_LOADED:
        return
    from agentauth.capabilities.identity_adapters import agentauth as _a
    from agentauth.capabilities.identity_adapters import auth0 as _auth0
    from agentauth.capabilities.identity_adapters import aws_sts as _aws
    from agentauth.capabilities.identity_adapters import azure_ad as _azure
    from agentauth.capabilities.identity_adapters import gcp as _gcp
    from agentauth.capabilities.identity_adapters import oidc as _oidc
    from agentauth.capabilities.identity_adapters import spiffe_jwt as _spiffe

    for mod in (_a, _spiffe, _oidc, _auth0, _aws, _azure, _gcp):
        register_identity_provider(mod.provider)
    _BUILTINS_LOADED = True
