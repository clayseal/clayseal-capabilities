"""Glue between identity sessions and L2 execution contexts."""
from __future__ import annotations

from typing import Any

from agentauth.core.authority_binding import AuthorityBinding
from agentauth.core.identity_protocol import CapabilityTokenBackend, IdentitySession
from agentauth.core.runtime import ActionDescriptor, AuthorityContext, ExecutionContext


def authority_from_session(session: IdentitySession) -> AuthorityContext:
    return session.binding.to_authority_context()


def execution_context_from_session(
    session: IdentitySession,
    *,
    action_name: str,
    resource_ref: str,
    input: dict[str, Any],
    query_id: str | None = None,
) -> ExecutionContext:
    return ExecutionContext(
        action=ActionDescriptor(action_name=action_name, resource_ref=resource_ref),
        input=input,
        authority=authority_from_session(session),
        query_id=query_id,
    )


def default_biscuit_backend() -> CapabilityTokenBackend:
    from agentauth.identity import _capabilities as caps

    class _BiscuitBackend:
        def attenuate(self, token_b64, *, root_public_hex, capabilities=None, path_patterns=None, denied_paths=None, expires_at=None):
            return caps.attenuate_biscuit(
                token_b64=token_b64,
                root_public_hex=root_public_hex,
                capabilities=capabilities,
                path_patterns=path_patterns,
                denied_paths=denied_paths,
                expires_at=expires_at,
            )

        def authorize(self, token_b64, *, root_public_hex, resource, action, file_path=None):
            return caps.authorize_biscuit(
                token_b64=token_b64,
                root_public_hex=root_public_hex,
                operation=(resource, action),
                pop=None,
                expected_htm="OFFLINE",
                expected_htu="agentauth:authorize",
                file_path=file_path,
            )

    return _BiscuitBackend()


def binding_for_provider(provider: str, raw: dict[str, Any], *, evidence_verified: bool = True) -> AuthorityBinding:
    from agentauth.capabilities.identity_adapters import get_identity_provider

    return get_identity_provider(provider).to_binding(raw, evidence_verified=evidence_verified)
