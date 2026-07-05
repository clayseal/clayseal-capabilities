"""Pluggable L1 identity provider adapters (5 common stacks)."""
from __future__ import annotations

from agentauth.capabilities.identity_adapters.registry import (
    get_identity_provider,
    list_identity_providers,
    register_identity_provider,
)

__all__ = [
    "get_identity_provider",
    "list_identity_providers",
    "register_identity_provider",
]
