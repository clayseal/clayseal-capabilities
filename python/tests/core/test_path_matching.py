"""Path-scope containment: canonicalization + root-escape defense.

Regression for a file-scope bypass — the matcher fnmatch'd raw paths, so `../`, `./`,
and `//` could evade allow/deny patterns (or escape the permitted root).
"""
from __future__ import annotations

from agentauth.core.path_matching import evaluate_path_scope, normalize_path, path_escapes_root


def _allowed(path, *, allow=(), deny=()):
    return evaluate_path_scope(path, allowed_paths=list(allow), denied_paths=list(deny))[0]


def test_traversal_cannot_escape_an_allowlist():
    # `src/../secrets/x` string-matches `src/*` but resolves to `secrets/x`.
    assert _allowed("src/../secrets/prod.env", allow=["src/*"]) is False
    assert _allowed("src/app/main.py", allow=["src/*"]) is True  # clean path still allowed


def test_dot_and_double_slash_cannot_evade_a_denylist():
    assert _allowed("./secrets/prod.env", allow=["*"], deny=["secrets/*"]) is False
    assert _allowed("secrets//prod.env", allow=["*"], deny=["secrets/*"]) is False
    assert _allowed("secrets/prod.env", allow=["*"], deny=["secrets/*"]) is False


def test_paths_escaping_root_are_denied_regardless_of_patterns():
    assert _allowed("src/../../etc/passwd", allow=[], deny=["*.env"]) is False
    assert _allowed("/etc/passwd", allow=["*"]) is False
    assert _allowed("../outside", allow=["*"]) is False
    assert path_escapes_root("a/../../b") is True
    assert path_escapes_root("a/b/c") is False


def test_normalize_path():
    assert normalize_path("./a//b/../c") == "a/c"
    assert normalize_path("a\\b\\c") == "a/b/c"
