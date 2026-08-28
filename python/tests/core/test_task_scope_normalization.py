"""Path normalization in scope matching.

Regression tests for a traversal bypass found by the adaptive red-team harness
in the capabilities repo (benchmarks/adversarial/adaptive.py). Before the fix,
`path_matches_any("/app/../etc/passwd", ["/app/**"])` returned True: fnmatch saw
a string beginning "/app/" and matched, while an `open()` on the same string
reads /etc/passwd. Every rung of the enforcement ladder that scopes by path
inherited the bypass, and the protected-zone list missed it too because it
string-matches the same unresolved input.

The property under test is simple to state and easy to regress: a scope decision
must be made about the file that will actually be opened.
"""
from __future__ import annotations

import pytest

from clayseal.core.task_scope import normalize_scope_path, path_matches_any

WORKSPACE = ["app/**", "/app/**"]


# --------------------------------------------------------------------------- #
# The bypass
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("attack", [
    "/app/../etc/passwd",
    "/app/../../etc/passwd",
    "/app/./../../etc/shadow",
    "/app/data/../../root/.ssh/id_rsa",
    "/app/a/b/../../../etc/passwd",
    "//app/../etc/passwd",
])
def test_traversal_out_of_the_workspace_is_denied(attack):
    assert not path_matches_any(attack, WORKSPACE), f"{attack} escaped the workspace"


def test_traversal_above_root_clamps_like_posix():
    """`/..` is `/` on every POSIX system; wrapping instead would let a path
    with enough `..` segments land back inside a granted prefix."""
    assert normalize_scope_path("/../etc/passwd") == "/etc/passwd"
    assert normalize_scope_path("/../../../app/x") == "/app/x"


# --------------------------------------------------------------------------- #
# Legitimate paths must still pass
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("legit", [
    "/app/data/report.txt",
    "/app/./data/report.txt",
    "/app/data/../out/report.txt",   # stays inside after resolution
    "app/data/report.txt",
    "//app/data/report.txt",
])
def test_in_scope_paths_still_match(legit):
    assert path_matches_any(legit, WORKSPACE), f"{legit} wrongly denied"


def test_normalization_is_idempotent():
    for path in ["/app/../etc/passwd", "/app/./x/../y", "app/z", "/"]:
        once = normalize_scope_path(path)
        assert normalize_scope_path(once) == once


# --------------------------------------------------------------------------- #
# Non-filesystem refs must survive untouched
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("ref", [
    "net:198.51.100.7",
    "file:/etc/passwd",
    "repo_write://org/repo",
    "mcp:tool:send_email",
])
def test_namespaced_refs_pass_through(ref):
    """Splitting these on `/` would eat the scheme and corrupt the match."""
    assert normalize_scope_path(ref) == ref


def test_patterns_are_normalized_too():
    """A pattern authored with redundant segments must still match, otherwise
    the fix would silently deny legitimate work."""
    assert path_matches_any("/app/data/x.txt", ["/app/./data/**"])
    assert path_matches_any("/app/data/x.txt", ["/app/foo/../data/**"])


def test_trailing_slash_is_preserved():
    """Directory-shaped patterns depend on it."""
    assert normalize_scope_path("/app/") == "/app/"
    assert normalize_scope_path("/app") == "/app"


def test_empty_path_is_not_mangled():
    assert normalize_scope_path("") == ""
