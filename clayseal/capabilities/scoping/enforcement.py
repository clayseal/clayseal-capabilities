"""Is this repository path inside the lease?

The check the scoping layer exists to perform, plus the normalisation it needs
first. `normalize_repo_path` and `resource_ref_to_repo_path` bring the many ways
a path arrives — a bare path, a `repo://` reference, a `file:` reference — to one
spelling before `check_repo_path_allowed` compares it to the lease.

Normalising before comparing is the whole game. This repository has already
shipped one deny-list bypass where two matchers disagreed about whether a
backslash was a separator, so the rule is that a path is canonicalised once and
compared once, never compared in whatever form it arrived in.
"""
from __future__ import annotations

import fnmatch

from clayseal.capabilities.scoping.models import CapabilityLease


def _path_glob_match(path: str, pattern: str) -> bool:
    """Segment-aware glob match: ``*``/``?``/``[...]`` are bounded to a single
    path segment (they do NOT cross ``/``), while a ``**`` segment spans zero or
    more segments. This stops ``src/*`` matching ``src/deep/secret.py``, plain
    :func:`fnmatch.fnmatch` lets ``*`` swallow ``/`` and over-grants. Inputs are
    already normalized (repo-relative, no ``.``/``..``) by ``normalize_repo_path``.
    """
    return _match_segments(path.split("/"), pattern.split("/"))


def _match_segments(path_segs: list[str], pat_segs: list[str]) -> bool:
    if not pat_segs:
        return not path_segs
    head, *rest = pat_segs
    if head == "**":
        # ** matches zero or more path segments.
        return any(_match_segments(path_segs[i:], rest) for i in range(len(path_segs) + 1))
    if not path_segs:
        return False
    # Neither a single pattern segment nor a single path segment contains '/',
    # so fnmatch's '*'/'?' cannot cross a directory boundary here.
    if fnmatch.fnmatchcase(path_segs[0], head):
        return _match_segments(path_segs[1:], rest)
    return False


def normalize_repo_path(file_path: str) -> str | None:
    """Canonical repo-relative path, or None when traversal/absolute paths are attempted."""
    if not file_path or "\x00" in file_path:
        return None
    normalized = file_path.replace("\\", "/").strip()
    if normalized.startswith("/"):
        return None
    parts: list[str] = []
    for part in normalized.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            return None
        parts.append(part)
    return "/".join(parts)


def resource_ref_to_repo_path(resource_ref: str | None) -> str | None:
    if not resource_ref:
        return None
    if resource_ref.startswith("repo_write://"):
        return resource_ref.removeprefix("repo_write://").lstrip("/")
    if resource_ref.startswith("repo_read://"):
        return resource_ref.removeprefix("repo_read://").lstrip("/")
    if resource_ref.startswith("repo://"):
        return resource_ref.removeprefix("repo://").lstrip("/")
    if resource_ref.startswith("file:"):
        return resource_ref.removeprefix("file:").lstrip("/")
    if "://" not in resource_ref:
        return resource_ref.lstrip("/")
    return None


def check_repo_path_allowed(
    file_path: str,
    lease: CapabilityLease,
    *,
    write: bool = False,
) -> tuple[bool, str]:
    normalized = normalize_repo_path(file_path)
    if normalized is None:
        return False, "invalid_path"
    for explicit in lease.explicit_allow_resources:
        target = resource_ref_to_repo_path(explicit) or explicit
        target_norm = normalize_repo_path(target.replace("repo://", ""))
        if target_norm and _path_glob_match(normalized, target_norm):
            return True, "explicit_allow"
    if write:
        allowed = set(lease.write_files)
    else:
        allowed = lease.read_files | lease.write_files
    if normalized in allowed:
        return True, "lease_allowlist"
    for pattern in allowed:
        pattern_norm = normalize_repo_path(pattern)
        if pattern_norm and _path_glob_match(normalized, pattern_norm):
            return True, "lease_glob"
    return False, "out_of_scope"
