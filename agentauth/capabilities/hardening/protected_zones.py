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
    # Procfs re-entry. `/proc/self/root` is the process's own root directory, so
    # any path under it addresses the whole filesystem again with a prefix no
    # deny-list entry above would recognize. `/proc/<pid>/environ` and `mem`
    # hand over another process's environment and memory directly. Found by the
    # adaptive red-team harness, which reached /etc/passwd through
    # /proc/self/root/etc/passwd while every pattern above matched nothing.
    "proc/*/root/**", "proc/self/root/**",
    "proc/*/environ", "proc/self/environ",
    "proc/*/mem", "proc/self/mem",
    "proc/*/cmdline", "proc/self/cmdline",
)


def _normalize(path: str) -> str:
    """Canonicalize before matching.

    Resolving ``..`` first is not optional: a deny-list that matches raw strings
    is bypassed by ``/app/../etc/passwd``, which no pattern above matches and
    which opens ``/etc/passwd``. This module's whole purpose is to be the check
    that cannot be widened by anything the agent influences, and an unresolved
    path is exactly such a widening. Same fix, and same reasoning, as
    ``agentauth.core.task_scope.normalize_scope_path``.
    """
    from agentauth.core.task_scope import normalize_scope_path

    resolved = normalize_scope_path(path.strip())
    return resolved.lstrip("/").lower()


def _exception_covers(path: str, norm: str, allow_exceptions: set[str]) -> bool:
    """Whether an operator-granted exception authorizes this path.

    Exceptions are matched as **globs**, not just as exact strings. Callers pass
    the compiled task scope's ``allowed_paths``, which are patterns like
    ``/records/**``, and an exact-membership test can never match one of those.
    The effect was a silent, unfixable false block: a support agent whose
    mandate explicitly granted ``/records/**`` was still hard-denied every file
    under it whose name contained "credential", with no way for the operator to
    authorize it, because the documented escape hatch did not accept the shape
    the caller actually supplies. That is friction with no security benefit,
    since the operator had already granted the path.

    Exact strings still work, so a narrow single-file exception behaves exactly
    as before.
    """
    if path in allow_exceptions or norm in {_normalize(a) for a in allow_exceptions}:
        return True
    return any(
        fnmatch.fnmatchcase(norm, _normalize(pattern))
        for pattern in allow_exceptions
        if "*" in pattern or "?" in pattern
    )


def is_protected_path(
    path: str,
    *,
    patterns: tuple[str, ...] = DEFAULT_PROTECTED_PATTERNS,
    allow_exceptions: set[str] | None = None,
) -> bool:
    """True when ``path`` falls in a protected zone and is not explicitly allowed.

    Total by contract: for any input this returns a decision and never raises.
    That is not a nicety for a deny-list — a deny-list is allow-by-default, which
    makes an unreadable path the *dangerous* direction. "I cannot parse this,
    therefore it is not protected" is precisely the fail-open that
    ``benchmarks/stress_gates.py`` exists to find, and before this guard a
    ``list``, ``dict`` or ``bool`` raised ``AttributeError`` out of the check.
    Upstream, ``broker._action_path`` filters to ``isinstance(v, str)`` so the
    shipped gateway never reached it; this is public API and the supported
    integration path is a caller's own gateway, which has no such filter.

    A non-string path is malformed rather than merely unusual, so it is treated
    as protected instead of coerced. Guessing what ``[1]`` meant as a path is how
    a zone check ends up admitting something nobody wrote.
    """
    if not isinstance(path, str):
        return True
    if not path:
        return False
    norm = _normalize(path)
    if allow_exceptions and _exception_covers(path, norm, allow_exceptions):
        return False

    # Match the resolved form AND the literal form. Lexical resolution is
    # unsound wherever a component is a symlink: `/proc/self/root` links to
    # `/`, so `/proc/self/root/app/../../etc/passwd` resolves lexically to
    # `/proc/self/etc/passwd` (which matches nothing) while the kernel opens
    # `/etc/passwd`. Popping a symlinked component is simply the wrong
    # operation, and no string function can know which components are links.
    #
    # For a deny-list, testing both forms is always safe: it can only deny
    # more, never less, and a false deny here costs one explicit exception
    # while a false allow costs the credential store. The allow-side check in
    # core.task_scope cannot use this trick, which is why symlink containment
    # ultimately belongs at the syscall boundary where paths are resolved for
    # real.
    literal = path.strip().lstrip("/").lower()
    return any(
        fnmatch.fnmatchcase(candidate, _normalize(pat))
        for pat in patterns
        for candidate in ({norm, literal})
    )


def protected_reason(path: str, **kwargs) -> str | None:
    return f"protected zone: {path!r} matches a sensitive-path pattern" if is_protected_path(path, **kwargs) else None
