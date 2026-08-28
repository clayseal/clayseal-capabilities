"""Path-pattern matching semantics shared across layers (Seam: file scope).

Biscuit-specific fact extraction stays in ``agentauth.identity.biscuit_scope``
(L1); the matching rules live here so capabilities (L2) and receipts (L3)
evaluate scope identically.

**THIS IS NOT THE ONLY IMPLEMENTATION, and it is not the one the gateway calls.**
This file claimed to be "the canonical home" while ``task_scope.py`` carried a
second ``path_matches_any`` with its own ``normalize_scope_path``, and that
second one is what ``task_scope_allows_path`` uses, which is what the broker's
floor uses. A differential fuzz over 39,403 comparisons found **3,298
disagreements**: they normalise trailing slashes differently, this one folds
backslashes to forward slashes and that one does not, and only that one sits in
the hot path behind an ``lru_cache``.

One of those divergences was a deny-list bypass rather than a curiosity. With
``denied_paths=["infra/prod/**"]`` the live matcher ALLOWED
``infra\\prod\\web.tf``, because it read the backslashes as filename
characters while this file read them as separators. ``task_scope_allows_path``
now evaluates every reading of an ambiguous path and resolves against the agent
in both directions.

They are kept separate because the semantics genuinely differ and merging them
would silently change one caller's behaviour. What is not acceptable is the
divergence being invisible, so ``python/tests/test_path_matcher_agreement.py``
asserts they agree on the cases where a disagreement would be a security
difference, and bounds the overall rate so a change to either normaliser has to
move a number someone looks at.
"""
from __future__ import annotations

import fnmatch
import posixpath

#: The sentinel a non-string yields. It matches no pattern, so an allow-list
#: never admits it and a deny-list never has to enumerate it.
UNMATCHABLE = "\x00<not-a-path>"


def normalize_path(path: str) -> str:
    """Canonicalize a path for scope matching: unify separators and collapse ``.`` /
    ``..`` / ``//``. Without this, a denied/allowed pattern can be evaded by a
    non-canonical spelling of the same path (``./secrets/x``, ``a//b``) or escaped with
    traversal (``src/../secrets/x`` matches ``src/*`` but resolves elsewhere).

    A non-string is not a path. It used to reach `posixpath.normpath` and raise
    `TypeError` from inside the authorization decision, which
    `benchmarks/stress_gates.py` has reported for five of its twenty adversarial
    inputs (`None`, `0`, `[1]`, `{'a': 1}`, `True`) while calling task-scope the
    only gate of six that raises. A gate that raises has not contained anything;
    it has crashed, and this repository's own replay harness says so in as many
    words. It now returns a sentinel that matches nothing, so an unusual input
    fails closed rather than escaping through an exception."""
    if not isinstance(path, str):
        return UNMATCHABLE
    return posixpath.normpath(path.strip().replace("\\", "/"))


def path_escapes_root(path: str) -> bool:
    """True if the (normalized) path is absolute or climbs above the permitted root.

    A non-string counts as escaping: it cannot be shown to be inside the root,
    and "cannot be shown to be inside" has to mean outside.
    """
    norm = normalize_path(path)
    if norm == UNMATCHABLE:
        return True
    return norm.startswith("/") or norm == ".." or norm.startswith("../")


def path_matches_any(path: str, patterns: list[str]) -> bool:
    normalized = normalize_path(path)
    for pattern in patterns:
        if not isinstance(pattern, str):
            # A malformed PATTERN is a control-plane bug rather than an attack,
            # and skipping it is the only option that does not either crash the
            # decision or silently widen the list it belongs to.
            continue
        if fnmatch.fnmatchcase(normalized, pattern.strip()):
            return True
    return False


def evaluate_path_scope(
    file_path: str | None,
    *,
    allowed_paths: list[str],
    denied_paths: list[str],
) -> tuple[bool, str]:
    """Return ``(allowed, reason)`` for a file path against token path facts."""
    if file_path is None:
        return True, "no file path presented"
    # A path that resolves outside the permitted root is never in scope, whatever the
    # allow/deny patterns say.
    if path_escapes_root(file_path):
        return False, f"path {file_path!r} escapes the permitted root"
    if denied_paths and path_matches_any(file_path, denied_paths):
        return False, f"path {file_path!r} matches a denied_path pattern"
    if allowed_paths and not path_matches_any(file_path, allowed_paths):
        return False, f"path {file_path!r} is outside allowed_path patterns"
    return True, "path scope satisfied"
