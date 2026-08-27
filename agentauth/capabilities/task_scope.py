"""TaskScope compilation, canonical home: ``agentauth.core.task_scope``.

The contract (TaskScope shape, compilation from mandates/authorizations, path
enforcement) lives in the core package; this module re-exports it and adds the
one capability-layer-specific operation, narrowing a Biscuit token to a
compiled scope, which needs a ``CapabilityTokenBackend``.
"""

from __future__ import annotations

from typing import Any

from agentauth.core.task_scope import (
    HUMAN_AUTHORIZATION_SCHEMA,
    TaskScope,
    action_path_candidates,
    apply_task_scope_to_authority,
    compile_human_authorization,
    compile_mandate_scope,
    compile_task_scope,
    compile_task_scope_envelope,
    path_matches_any,
    resolve_task_mandate,
    resource_scope_entries,
    task_scope_allows_path,
)

__all__ = [
    "HUMAN_AUTHORIZATION_SCHEMA",
    "TaskScope",
    "action_path_candidates",
    "apply_task_scope_to_authority",
    "attenuate_biscuit_for_scope",
    "compile_human_authorization",
    "compile_mandate_scope",
    "compile_task_scope",
    "compile_task_scope_envelope",
    "path_matches_any",
    "resolve_task_mandate",
    "resource_scope_entries",
    "task_scope_allows_path",
]


def attenuate_biscuit_for_scope(
    *,
    token_b64: str,
    root_public_hex: str,
    scope: TaskScope,
    capabilities: list[dict] | None = None,
    backend: Any | None = None,
) -> str:
    """Narrow a Biscuit token to a compiled task scope (SM-7)."""
    if backend is None:
        from agentauth.capabilities.integration import default_biscuit_backend

        backend = default_biscuit_backend()
    return backend.attenuate(
        token_b64,
        root_public_hex=root_public_hex,
        capabilities=capabilities,
        path_patterns=list(scope.allowed_paths) or None,
        denied_paths=list(scope.denied_paths) or None,
    )
