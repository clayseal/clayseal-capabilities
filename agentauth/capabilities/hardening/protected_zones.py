"""Protected zones: paths that are denied regardless of the task's own scope.

A goal's path scope says what the task *may* touch. Protected zones say what no
task may touch without an explicit, separately-authorized exception: private
keys, credential stores, environment files, cloud-credential directories, VCS
internals. This closes the path-exfiltration gap where a goal that grants a
broad read surface (or none at all) would otherwise let an injected step read
``secrets/prod.env`` through an allowed read tool.

The check is a global deny-list applied before the goal's own allow/deny path
scope, so it cannot be widened by anything the agent influences. An operator can
grant a scoped exception by listing the exact path in the goal's explicit allow
resources, which the caller passes as ``allow_exceptions``.
"""
from __future__ import annotations

import fnmatch

# Sensitive path globs, matched case-insensitively against a normalized path.
DEFAULT_PROTECTED_PATTERNS: tuple[str, ...] = (
    "secrets/*", "secrets/**", "**/secrets/*", "**/secrets/**",
    "*.pem", "**/*.pem", "id_rsa", "**/id_rsa", "id_rsa.*", "**/id_rsa.*",
    ".env", "**/.env", ".env.*", "**/.env.*",
    "credentials", "**/credentials", "**/credentials.*",
    ".aws/*", "**/.aws/**", ".ssh/*", "**/.ssh/**",
    ".git/*", "**/.git/**",
    "etc/shadow", "etc/passwd", "**/.netrc", "**/.npmrc", "**/.pypirc",
    "**/*token*", "**/*secret*", "**/*password*", "**/*api_key*",
)


def _normalize(path: str) -> str:
    return path.strip().lstrip("./").lstrip("/").lower()


def is_protected_path(
    path: str,
    *,
    patterns: tuple[str, ...] = DEFAULT_PROTECTED_PATTERNS,
    allow_exceptions: set[str] | None = None,
) -> bool:
    """True when ``path`` falls in a protected zone and is not explicitly allowed."""
    if not path:
        return False
    norm = _normalize(path)
    if allow_exceptions and (path in allow_exceptions or norm in {_normalize(a) for a in allow_exceptions}):
        return False
    return any(fnmatch.fnmatchcase(norm, _normalize(pat)) for pat in patterns)


def protected_reason(path: str, **kwargs) -> str | None:
    return f"protected zone: {path!r} matches a sensitive-path pattern" if is_protected_path(path, **kwargs) else None
