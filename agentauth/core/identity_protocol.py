"""Provider-neutral identity contracts for cross-layer integration."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from agentauth.core.authority_binding import AuthorityBinding

CapabilityAuthorizer = Callable[[str, str], dict[str, Any]]


@dataclass
class IdentitySession:
    """Normalized session after a provider verifies attestation."""

    binding: AuthorityBinding
    provider: str
    capability_authorizer: CapabilityAuthorizer | None = None
    raw_credential: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class IdentityProvider(Protocol):
    """Alternate L1 backends implement this; L2/L3 consume IdentitySession."""

    name: str

    def to_binding(self, raw: dict[str, Any], *, evidence_verified: bool = False) -> AuthorityBinding:
        """Map provider credential claims → AuthorityBinding."""

    def build_session(
        self,
        raw: dict[str, Any],
        *,
        capability_authorizer: CapabilityAuthorizer | None = None,
        evidence_verified: bool = False,
    ) -> IdentitySession:
        ...


@runtime_checkable
class CapabilityTokenBackend(Protocol):
    """Optional L2 capability-token operations (Biscuit, macaroons, etc.)."""

    def attenuate(
        self,
        token_b64: str,
        *,
        root_public_hex: str,
        capabilities: list[dict] | None = None,
        path_patterns: list[str] | None = None,
        denied_paths: list[str] | None = None,
        expires_at: Any = None,
    ) -> str:
        ...

    def authorize(
        self,
        token_b64: str,
        *,
        root_public_hex: str,
        resource: str,
        action: str,
        file_path: str | None = None,
    ) -> dict[str, Any]:
        ...


@runtime_checkable
class CapabilityLayer(Protocol):
    """L3 consumes this to stay agnostic of the L2 implementation."""

    name: str

    def issue_commit_token(self, ctx: Any, *, key: Any, ttl_seconds: int) -> Any:
        ...

    def verify_commit_token(self, signed: Any, *, ctx: Any) -> tuple[bool, str | None]:
        ...

    def compile_task_scope(self, mandate: dict[str, Any]) -> Any:
        ...
