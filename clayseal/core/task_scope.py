"""Compile signed task mandates into L3 authority scope (SM-6)."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

from clayseal.core.mandate import MANDATE_SCHEMA, Mandate

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
    # When the grant stops authorizing anything, ISO 8601.
    #
    # This was dropped on the floor. Every mandate schema carries `expires_at`,
    # thirteen benchmark loaders write one, and the compiled scope did not keep
    # it: a grant that expired four hundred days ago compiled cleanly and the
    # broker allowed the action. An expiry nobody reads is not a control.
    expires_at: str | None = None

    def __post_init__(self) -> None:
        # Close the deny list here rather than only where a policy is compiled.
        # `close_deny_patterns` was written for `policy.py` and applied only on
        # that path, so a `TaskScope` built directly, which the library API
        # invites and which every benchmark loader does, kept the hole: a
        # randomized differential over 200,000 paths found `data/secrets`
        # ALLOWED under `denied_paths=["data/secrets/**"]`. A fix that only one
        # construction path reaches is a fix for one construction path.
        if self.denied_paths:
            self.denied_paths = close_deny_patterns(self.denied_paths)

    def is_expired(self, now: datetime | None = None) -> bool:
        """Has this grant stopped authorizing?

        A scope with no expiry never expires, so a mandate written before this
        field existed behaves exactly as it did. An UNPARSEABLE expiry counts as
        expired: a grant whose validity cannot be established is not a valid
        grant, and the alternative fails open.
        """
        if not self.expires_at:
            return False
        moment = now or datetime.now(timezone.utc)
        try:
            deadline = datetime.fromisoformat(str(self.expires_at))
        except ValueError:
            return True
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=timezone.utc)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment > deadline

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
        expires_at=getattr(mandate, "expires_at", None),
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
        expires_at=(str(document["expires_at"])
                    if document.get("expires_at") else None),
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
    from clayseal.core.resource_refs import is_resource_ref

    return is_resource_ref(raw)


#: What a non-path normalises to. Contains a NUL, so no authored pattern can
#: match it by accident.
UNMATCHABLE_PATH = "\x00<not-a-path>"


def normalize_scope_path(path: str) -> str:
    """Type guard in front of the cached implementation.

    The guard cannot live inside the cached function: `lru_cache` hashes its
    argument before the body runs, so an unhashable one (`[1]`, `{'a': 1}`)
    raises `TypeError` from the decorator and never reaches an `isinstance`
    check. That is two of the five adversarial inputs `stress_gates` reports,
    and it is why this wrapper exists rather than one more line in the body.
    """
    if not isinstance(path, str):
        return UNMATCHABLE_PATH
    return _normalize_scope_path(path)


def close_deny_patterns(deny: list[str]) -> list[str]:
    """`deny: ["infra/prod/**"]` must also deny `infra/prod`.

    `**` requires at least one segment after the slash, so a pattern written to
    exclude a directory does not exclude the directory itself. Measured: with
    `denied_paths=["infra/prod/**"]`, the path `infra/prod` was ALLOWED. A tool
    that takes a directory rather than a file, which is most infrastructure
    tooling, walks straight through a rule its author believed covered it.

    Only DENY patterns are closed this way. Doing the same to an allow-list would
    widen it, and widening an allow-list because of a pattern-syntax detail is
    the opposite of what an author means.

    Idempotent: the parent it appends carries no `/**` suffix, so a second pass
    adds nothing. `TaskScope.__post_init__` applies it, and `policy.py` calls it
    too, so a scope closed twice is the same scope.
    """
    out = list(deny)
    for pattern in deny:
        if not isinstance(pattern, str):
            continue
        base = pattern.rstrip("/")
        for suffix in ("/**", "/*"):
            if base.endswith(suffix):
                parent = base[: -len(suffix)]
                if parent and parent not in out:
                    out.append(parent)
                break
    return out


@lru_cache(maxsize=8192)
def _normalize_scope_path(path: str) -> str:
    """Lexically resolve ``.`` and ``..`` before a path is matched against scope.

    Without this, scope matching is a string comparison and ``/app/**`` admits
    ``/app/../etc/passwd``: fnmatch sees a string starting with ``/app/`` and
    says yes, while the filesystem opens ``/etc/passwd``. An adaptive red-team
    run against the enforcement ladder found exactly that, and the protected-zone
    list did not catch it either, because it string-matches the same unresolved
    input. Any authorization decision made on an unresolved path is decided
    about a file other than the one that will be opened.

    Resolution is lexical, not filesystem-backed: no ``realpath``, no disk
    access, no symlink following. That keeps the function pure and usable in
    replay and offline policy compilation. It also means a symlink inside the
    granted workspace pointing outside it is *not* caught here. That is a real
    residual, and it is the reason the syscall-boundary enforcement layer
    matters: the kernel resolves symlinks, string matching cannot.

    Traversal above the root is clamped rather than wrapped, so ``/../etc`` is
    ``/etc``, matching POSIX behaviour where ``/..`` is ``/``.

    Cached because this sits in the enforcement hot path, called once per
    candidate path *and* once per scope pattern on every decision. Uncached it
    took the `task-scope` rung from 2 us to 48 us per decision. The function is
    pure over a small repeating input set, so the cache costs nothing in
    correctness.
    """
    if not path:
        return path
    # Namespaced refs (``net:host``, ``file:...``) are not filesystem paths and
    # must pass through untouched or their prefix would be eaten as a segment.
    if ":" in path.split("/", 1)[0]:
        return path

    absolute = path.startswith("/")
    trailing = path.endswith("/") and len(path) > 1
    parts: list[str] = []
    for raw_segment in path.split("/"):
        # A segment is classified by its STRIPPED form. Without that, a
        # whitespace-decorated segment is treated as an ordinary directory name
        # and absorbs the `..` that follows it: `\t./../out/sub` resolved to
        # `out/sub` and was ALLOWED under `out/**`, while `../out/sub`, the same
        # path without the tab, was correctly denied. A space or a tab in front
        # of a traversal defeated the traversal handling entirely.
        #
        # Whether the filesystem itself would open `" .."` as a literal
        # directory is not the question. Plenty of consumers trim a path before
        # opening it, and this function's whole purpose, stated above, is that
        # an authorization decision must be about the file that will actually be
        # opened. Where the two readings can differ, the safe one is the one
        # that keeps the traversal.
        segment = raw_segment.strip()
        if segment in ("", "."):
            continue
        if segment == "..":
            if parts and parts[-1] != "..":
                parts.pop()
            elif not absolute:
                # A relative path may legitimately climb above its own base;
                # keep the marker so it cannot be confused with the base itself.
                parts.append("..")
            continue
        parts.append(raw_segment)

    resolved = "/".join(parts)
    if absolute:
        resolved = "/" + resolved
    if trailing and not resolved.endswith("/"):
        resolved += "/"
    return resolved or ("/" if absolute else "")


def path_matches_any(path: str, patterns: list[str]) -> bool:
    """Glob match, on the resolved path and against resolved patterns.

    Both sides are normalized: a pattern is authored by a human and may itself
    contain redundant segments, and matching a resolved path against an
    unresolved pattern would reintroduce the mismatch this is here to close.
    """
    resolved = normalize_scope_path(path)
    for pattern in patterns:
        if not isinstance(pattern, str):
            # A malformed PATTERN is a control-plane bug rather than an attack.
            # Skipping it is the only option that neither crashes the decision
            # nor silently widens the list the pattern belongs to.
            continue
        if fnmatch.fnmatchcase(resolved, normalize_scope_path(pattern)):
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


def path_readings(path: str) -> tuple[str, ...]:
    """Every string this path could reasonably be understood to mean.

    A backslash is a separator on Windows and a legal filename character on
    POSIX, so `infra\\prod\\web.tf` is two different paths depending on who
    reads it. This matcher read it one way and the one in `path_matching.py`
    read it the other, which a differential fuzz over 39,403 comparisons found
    as 3,298 disagreements. The consequence was a deny-list bypass: with
    `denied_paths=["infra/prod/**"]`, `infra\\prod\\web.tf` was ALLOWED.

    Rather than picking a reading, the scope decision is evaluated against all of
    them. A path is denied if ANY reading is denied and allowed only if EVERY
    reading is allowed, so ambiguity resolves against the agent in both
    directions. That is the same rule the MCP proxy applies to percent-encoded
    and NUL-bearing paths, for the same reason: a check is only as good as the
    agreement between the string it examined and the string that gets opened.
    """
    if not isinstance(path, str):
        return (UNMATCHABLE_PATH,)
    readings = [path]
    if "\\" in path:
        readings.append(path.replace("\\", "/"))
    return tuple(dict.fromkeys(readings))


def _deny_readings(path: str) -> tuple[str, ...]:
    """Readings that matter only for the DENY side of the decision.

    Two spellings reach the same file on a filesystem this library cannot see:

    - **Case.** macOS and Windows are case-insensitive, so `workspace/SECRETS/k`
      opens the file `workspace/secrets/**` denies. `fnmatchcase` compares
      exactly, so the deny-list missed it.
    - **Trailing dots and spaces.** Win32 strips them, so `workspace/secrets./k`
      and `workspace/secrets /k` open the same directory.

    These widen the deny check ONLY. They are deliberately not added to
    `path_readings`, because that would also make the ALLOW check stricter
    (allowed only if EVERY reading is allowed) and would start refusing paths
    that are genuinely distinct files on a case-sensitive filesystem. Widening
    deny costs at most a false denial on Linux for a directory that differs from
    a denied one only by case; narrowing allow would cost false denials
    everywhere. Only one of those is worth paying to close a bypass.
    """
    out = [path.lower()]
    stripped = "/".join(seg.rstrip(". ") for seg in path.replace("\\", "/").split("/"))
    out.append(stripped)
    out.append(stripped.lower())
    return tuple(dict.fromkeys(out))


def task_scope_allows_path(scope: TaskScope, path: str) -> bool:
    readings = path_readings(path)
    if scope.denied_paths:
        # Denied if ANY reading is denied.
        if any(path_matches_any(r, scope.denied_paths) for r in readings):
            return False
        # Same rule, over the spellings that reach the same file on a
        # case-insensitive or Win32 filesystem. Patterns are folded too, so the
        # comparison is symmetric and a deny-list written in either case works.
        if isinstance(path, str):
            folded = [p.lower() for p in scope.denied_paths if isinstance(p, str)]
            extra = _deny_readings(path)
            if any(path_matches_any(r, folded) for r in extra):
                return False
            if any(path_matches_any(r, list(scope.denied_paths)) for r in extra):
                return False
    if scope.allowed_paths:
        # Allowed only if EVERY reading is allowed.
        return all(path_matches_any(r, scope.allowed_paths) for r in readings)
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
    backend: Any | None = None,
) -> str:
    """Narrow a Biscuit token to a compiled task scope (SM-7).

    `backend` is resolved through the plugin registry when it is not supplied,
    which is what the registry is for: a consumer asks for a named backend
    without importing whatever package implements it.

    This used to import `clayseal.capabilities.integration` directly. That was
    an upward dependency from the contracts layer to the layer above it, invisible
    while the two were separate distributions because the import simply resolved
    at call time in an environment that had both. Vendoring core into this
    repository would have made it permanent, so it is inverted here rather than
    inherited. `clayseal.capabilities.task_scope` has its own wrapper that falls
    back to the identity layer, and callers who want that behaviour should use it.
    """
    if backend is None:
        from clayseal.core.plugins import get_plugin

        try:
            backend = get_plugin("capability_backends", "biscuit")
        except KeyError as exc:
            raise LookupError(
                "no capability-token backend named 'biscuit' is registered. "
                "Pass backend=..., register one with "
                "register_plugin('capability_backends', 'biscuit', ...), or use "
                "clayseal.capabilities.task_scope.attenuate_biscuit_for_scope, "
                "which falls back to the identity layer's Biscuit primitives."
            ) from exc
    return backend.attenuate(
        token_b64,
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
