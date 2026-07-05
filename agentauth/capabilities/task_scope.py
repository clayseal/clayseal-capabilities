"""Compile signed task mandates into L3 authority scope (SM-6)."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

from agentauth.capabilities.mandate import MANDATE_SCHEMA, Mandate

HUMAN_AUTHORIZATION_SCHEMA = "agentauth.human_authorization.v1"


@dataclass
class TaskScope:
    """Normalized task-scoped authority derived from a signed grant."""

    allowed_paths: list[str] = field(default_factory=list)
    denied_paths: list[str] = field(default_factory=list)
    allowed_actions: list[str] = field(default_factory=list)
    allowed_resources: list[str] = field(default_factory=list)
    task_summary: str | None = None
    mandate_id: str | None = None
    source_schema: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_paths": list(self.allowed_paths),
            "denied_paths": list(self.denied_paths),
            "allowed_actions": list(self.allowed_actions),
            "allowed_resources": list(self.allowed_resources),
            "task_summary": self.task_summary,
            "mandate_id": self.mandate_id,
            "source_schema": self.source_schema,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> TaskScope:
        return cls(
            allowed_paths=[str(item) for item in raw.get("allowed_paths", [])],
            denied_paths=[str(item) for item in raw.get("denied_paths", [])],
            allowed_actions=[str(item) for item in raw.get("allowed_actions", [])],
            allowed_resources=[str(item) for item in raw.get("allowed_resources", [])],
            task_summary=raw.get("task_summary"),
            mandate_id=raw.get("mandate_id"),
            source_schema=raw.get("source_schema"),
        )


def compile_mandate_scope(mandate: Mandate) -> TaskScope:
    """Map AP2-style ``agent-receipts.mandate.v1`` resources to task scope."""
    return TaskScope(
        allowed_resources=list(mandate.allowed_resources),
        allowed_actions=list(mandate.allowed_actions),
        mandate_id=mandate.grant_id,
        source_schema=MANDATE_SCHEMA,
    )


def compile_human_authorization(document: dict[str, Any]) -> TaskScope:
    """Map Devin demo ``agentauth.human_authorization.v1`` path scope."""
    scope = document.get("scope")
    if not isinstance(scope, dict):
        scope = {}
    task = document.get("task")
    summary = None
    if isinstance(task, dict):
        summary = task.get("summary")
    return TaskScope(
        allowed_paths=[str(item) for item in scope.get("allowed_paths", [])],
        denied_paths=[str(item) for item in scope.get("denied_paths", [])],
        allowed_actions=[str(item) for item in scope.get("allowed_operations", [])],
        task_summary=str(summary) if summary else None,
        mandate_id=str(document.get("mandate_id") or document.get("grant_id") or ""),
        source_schema=str(document.get("schema") or HUMAN_AUTHORIZATION_SCHEMA),
    )


def compile_task_scope(source: Mandate | dict[str, Any]) -> TaskScope:
    """Compile any supported mandate / authorization document."""
    if isinstance(source, Mandate):
        return compile_mandate_scope(source)

    if not isinstance(source, dict):
        raise TypeError("task scope source must be Mandate or dict")

    schema = str(source.get("schema", ""))
    if schema == MANDATE_SCHEMA:
        return compile_mandate_scope(Mandate.from_dict(source))
    if schema == HUMAN_AUTHORIZATION_SCHEMA:
        return compile_human_authorization(source)

    if "allowed_resources" in source or "grant_id" in source:
        return compile_mandate_scope(Mandate.from_dict(source))
    if "scope" in source:
        return compile_human_authorization(source)

    raise ValueError(f"unsupported task scope schema: {schema!r}")


def compile_task_scope_envelope(envelope: dict[str, Any]) -> TaskScope:
    """Compile from a signed envelope ``{document, signature}``."""
    document = envelope.get("document")
    if not isinstance(document, dict):
        raise ValueError("mandate envelope missing document")
    return compile_task_scope(document)


def resource_scope_entries(scope: TaskScope) -> list[str]:
    """Entries stored on ``AuthorityContext.resource_scope`` for the policy engine."""
    entries: list[str] = []
    for path in scope.allowed_paths:
        entries.append(f"file:{path}")
    for resource in scope.allowed_resources:
        if _is_resource_ref(resource):
            entries.append(resource)
        else:
            entries.append(f"resource:{resource}")
    return entries


def _is_resource_ref(raw: str) -> bool:
    from agentauth.core.resource_refs import is_resource_ref

    return is_resource_ref(raw)


def path_matches_any(path: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if fnmatch.fnmatchcase(path, pattern):
            return True
    return False


def action_path_candidates(
    *,
    resource_ref: str | None,
    touched_resources: list[str] | None = None,
) -> list[str]:
    paths: list[str] = []
    if resource_ref:
        if resource_ref.startswith("file:"):
            paths.append(resource_ref.removeprefix("file:"))
        elif resource_ref.startswith("repo_write://"):
            paths.append(resource_ref.removeprefix("repo_write://").lstrip("/"))
        elif resource_ref.startswith("repo_read://"):
            paths.append(resource_ref.removeprefix("repo_read://").lstrip("/"))
        elif resource_ref.startswith("repo://"):
            paths.append(resource_ref.removeprefix("repo://").lstrip("/"))
        elif resource_ref.startswith("repo:"):
            paths.append(resource_ref.removeprefix("repo:").lstrip("/"))
        elif "/" in resource_ref and ":" not in resource_ref:
            paths.append(resource_ref)
    for item in touched_resources or []:
        if item.startswith("file:"):
            paths.append(item.removeprefix("file:"))
        elif item.startswith("repo_write://"):
            paths.append(item.removeprefix("repo_write://").lstrip("/"))
        elif item.startswith("repo_read://"):
            paths.append(item.removeprefix("repo_read://").lstrip("/"))
        elif item.startswith("repo://"):
            paths.append(item.removeprefix("repo://").lstrip("/"))
        elif item.startswith("repo:"):
            paths.append(item.removeprefix("repo:").lstrip("/"))
    deduped: list[str] = []
    seen: set[str] = set()
    for path in paths:
        if path and path not in seen:
            seen.add(path)
            deduped.append(path)
    return deduped


def task_scope_allows_path(scope: TaskScope, path: str) -> bool:
    if scope.denied_paths and path_matches_any(path, scope.denied_paths):
        return False
    if scope.allowed_paths:
        return path_matches_any(path, scope.allowed_paths)
    return True


def apply_task_scope_to_authority(
    authority: Any,
    scope: TaskScope,
) -> None:
    """Mutate an ``AuthorityContext`` with compiled task scope entries."""
    authority.resource_scope = resource_scope_entries(scope)


def attenuate_biscuit_for_scope(
    *,
    token_b64: str,
    root_public_hex: str,
    scope: TaskScope,
    capabilities: list[dict] | None = None,
) -> str:
    """Narrow a Biscuit token to a compiled task scope (SM-7)."""
    from agentauth.identity._capabilities import attenuate_biscuit

    return attenuate_biscuit(
        token_b64=token_b64,
        root_public_hex=root_public_hex,
        capabilities=capabilities,
        path_patterns=list(scope.allowed_paths) or None,
        denied_paths=list(scope.denied_paths) or None,
    )


def resolve_task_mandate(
    task_mandate: Mandate | dict[str, Any],
) -> tuple[TaskScope, list[str]]:
    """Compile a mandate envelope or document into scope + resource_scope entries."""
    if isinstance(task_mandate, dict) and "document" in task_mandate:
        scope = compile_task_scope_envelope(task_mandate)
    else:
        scope = compile_task_scope(task_mandate)
    return scope, resource_scope_entries(scope)
