"""Glue between identity sessions and L2 execution contexts."""
from __future__ import annotations

from typing import Any

from clayseal.core.authority_binding import AuthorityBinding
from clayseal.core.identity_protocol import CapabilityTokenBackend, IdentitySession
from clayseal.core.runtime import ActionDescriptor, AuthorityContext, ExecutionContext


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
    """Resolve the capability-token backend.

    Resolution order: an explicitly registered/entry-point plugin named
    ``biscuit`` in the ``agentauth.capability_backends`` group wins; otherwise
    fall back to the built-in backend over the identity layer's Biscuit
    primitives (optional extra, identity is not a hard dependency of this
    layer).
    """
    from clayseal.core.plugins import get_plugin

    try:
        return get_plugin("capability_backends", "biscuit")
    except KeyError:
        pass

    try:
        from agentauth.identity import _capabilities as caps
    except ImportError as exc:
        raise ImportError(
            "The default Biscuit backend needs the identity layer. Install with: "
            "pip install 'clayseal[biscuit-service]', or register "
            "your own CapabilityTokenBackend under the "
            "'agentauth.capability_backends' entry-point group as 'biscuit'."
        ) from exc

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


def binding_for_provider(
    provider: str, raw: dict[str, Any], *, evidence_verified: bool = False
) -> AuthorityBinding:
    """Map ``raw`` provider claims to a binding via the named adapter.

    ``evidence_verified`` defaults to ``False``: a claim-mapping adapter trusts
    the caller to have verified the credential, so the caller must explicitly
    opt in to stamp the binding as verified.
    """
    from clayseal.capabilities.identity_adapters import get_identity_provider

    return get_identity_provider(provider).to_binding(raw, evidence_verified=evidence_verified)
