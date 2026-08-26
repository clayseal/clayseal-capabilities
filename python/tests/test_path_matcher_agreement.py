"""Two path matchers, one of which decides authorization.

`path_matching.py` called itself "the canonical home for allowed_path /
denied_path evaluation" while `task_scope.py` carried a second
`path_matches_any` with its own normaliser, and the second one is what
`task_scope_allows_path` calls, which is what the broker's floor calls.

A differential fuzz over 39,403 comparisons found 3,298 disagreements, and one
class of them was a deny-list bypass rather than a curiosity. These tests hold
the boundary: the bypasses stay closed, and the remaining divergence stays
visible instead of being discovered again in a year.
"""
from __future__ import annotations

import random

import pytest

from agentauth.core import path_matching as canonical
from agentauth.core import task_scope as live
from agentauth.core.task_scope import TaskScope, task_scope_allows_path


# --------------------------------------------------------------------------- #
# The bypasses
# --------------------------------------------------------------------------- #
def _deny_scope():
    return TaskScope(allowed_paths=["**"],
                     denied_paths=["infra/prod/**", "secrets/**"])


@pytest.mark.parametrize("path", [
    "infra/prod/web.tf",
    "infra\\prod\\web.tf",          # windows separators
    "secrets\\key.pem",
    "./infra/prod/web.tf",
    "infra//prod//web.tf",
    "infra/prod/",
])
def test_a_denied_path_stays_denied_however_it_is_spelled(path):
    """`infra\\prod\\web.tf` was ALLOWED against `denied_paths=['infra/prod/**']`.

    A backslash is a separator on Windows and a legal filename character on
    POSIX, so the string means two things. The matcher picked one; the other
    matcher picked the other. Both readings are now evaluated and a path is
    denied if any reading is denied.
    """
    assert task_scope_allows_path(_deny_scope(), path) is False, path


def test_an_allow_list_is_not_widened_by_the_same_ambiguity():
    """Ambiguity resolves against the agent in BOTH directions.

    Denied if any reading is denied, allowed only if every reading is allowed.
    Reading it the other way round would turn the fix into a way of entering an
    allow-list by spelling a path differently.
    """
    scope = TaskScope(allowed_paths=["infra/staging/**"])
    assert task_scope_allows_path(scope, "infra/staging/a.tf") is True
    assert task_scope_allows_path(scope, "infra\\staging\\a.tf") is False


def test_a_deny_pattern_covers_the_directory_it_names():
    """`deny: ['infra/prod/**']` did not deny `infra/prod`.

    `**` requires at least one segment after the slash, so a rule written to
    exclude a directory did not exclude the directory itself, and most
    infrastructure tooling takes a directory.
    """
    from agentauth.capabilities.policy import compile_policy

    policy = compile_policy({
        "version": 1, "goal": {"id": "q", "summary": "s"},
        "paths": {"allow": ["**"], "deny": ["infra/prod/**", ".git/**"]},
    })
    for path in ("infra/prod", "infra/prod/x.tf", ".git", ".git/config"):
        assert task_scope_allows_path(policy.scope, path) is False, path
    assert task_scope_allows_path(policy.scope, "infra/staging/x.tf") is True


def test_closing_deny_patterns_does_not_touch_the_allow_list():
    """Widening an allow-list over a pattern-syntax detail is the opposite of
    what an author means."""
    from agentauth.capabilities.policy import compile_policy

    policy = compile_policy({
        "version": 1, "goal": {"id": "q", "summary": "s"},
        "paths": {"allow": ["infra/staging/**"]},
    })
    assert policy.scope.allowed_paths == ["infra/staging/**"]
    assert task_scope_allows_path(policy.scope, "infra/staging") is False


# --------------------------------------------------------------------------- #
# Neither matcher may raise
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("value", [None, 0, [1], {"a": 1}, True, b"/app/x", 1.5])
def test_neither_matcher_raises_on_a_non_string(value):
    """`stress_gates.py` reported task-scope as the only gate of six that raises.

    A gate that raises has not contained anything, it has crashed. Two of these
    needed the guard OUTSIDE the `lru_cache`, because the decorator hashes its
    argument before the body runs.
    """
    scope = TaskScope(allowed_paths=["/app/**"], denied_paths=["/app/secret/**"])
    assert task_scope_allows_path(scope, value) is False
    assert canonical.path_matches_any(value, ["/app/**"]) is False
    assert live.path_matches_any(value, ["/app/**"]) is False


def test_a_malformed_pattern_is_skipped_rather_than_raising():
    scope = TaskScope(allowed_paths=["/app/**", None, 7], denied_paths=[None])
    assert task_scope_allows_path(scope, "/app/x") is True
    assert task_scope_allows_path(scope, "/etc/passwd") is False


# --------------------------------------------------------------------------- #
# The divergence that remains
# --------------------------------------------------------------------------- #
def test_the_two_matchers_agree_on_the_cases_that_decide_authorization():
    """Not full agreement: they normalise trailing slashes and patterns
    differently and merging them would silently change one caller. These are the
    cases where a disagreement would be a security difference."""
    cases = [
        ("app/x", ["app/**"]),
        ("app/../etc/passwd", ["app/**"]),
        ("./app/x", ["app/**"]),
        ("app//x", ["app/**"]),
        ("/app/x", ["/app/**"]),
        ("../etc/passwd", ["app/**"]),
        ("", ["**"]),
    ]
    for path, patterns in cases:
        assert canonical.path_matches_any(path, patterns) == \
            live.path_matches_any(path, patterns), (path, patterns)


def test_the_remaining_divergence_is_bounded_and_measured():
    """A regression that widened it would show as a jump in this rate.

    The number is not zero and is not meant to be. It is here so that a change to
    either normaliser has to move a number someone looks at.
    """
    random.seed(11)
    segs = ["a", "b", "..", ".", "", "secret", "app", "x.txt", "net:h"]
    pats = ["a/**", "a/*", "**", "/a/**", "*", "a/b", "secret/**", "**/x.txt"]
    paths = set()
    for k in (1, 2, 3):
        for _ in range(300):
            p = "/".join(random.choice(segs) for _ in range(k))
            paths.add(p)
            paths.add("/" + p)

    total = disagree = 0
    for path in paths:
        for pattern in pats:
            total += 1
            if canonical.path_matches_any(path, [pattern]) != \
                    live.path_matches_any(path, [pattern]):
                disagree += 1
    rate = disagree / total
    assert rate < 0.15, (
        f"the two matchers now disagree on {rate:.1%} of {total} comparisons. "
        f"They are allowed to differ on trailing slashes and pattern "
        f"normalisation; a jump here means something else moved."
    )


# ------------------------------------- found by fuzzing the floor, 2026-08 ---
@pytest.mark.parametrize("path", [
    "\t./../out//sub/",
    " ../../data/x",
    "\t../../out//sub/../prod.txt",
    " ..//./../data/./.env/",
    "  ../out/sub",
])
def test_whitespace_does_not_absorb_a_traversal(path):
    """`../out/sub` was denied and `\\t./../out//sub/` was ALLOWED.

    The normaliser classified a segment by its raw form, so a
    whitespace-decorated segment counted as an ordinary directory name and the
    `..` after it popped that instead of climbing. Twenty escapes in the first
    60,000 generated paths, every one of that shape. Plenty of consumers trim a
    path before opening it, and a decision must be about the file that opens.
    """
    scope = TaskScope(allowed_paths=["out/**", "data/**"])
    assert not task_scope_allows_path(scope, path)


def test_a_directly_constructed_scope_closes_its_own_deny_list():
    """`close_deny_patterns` was applied only where a policy is compiled.

    A `TaskScope` built directly, which the API invites and every benchmark
    loader does, kept the hole: `**` needs a segment after the slash, so
    `data/secrets/**` did not deny `data/secrets` itself.
    """
    scope = TaskScope(allowed_paths=["data/**"],
                      denied_paths=["data/secrets/**"])
    assert "data/secrets" in scope.denied_paths
    for path in ("data/secrets", "data//secrets", "data/./secrets",
                 "data//infra/../ap/././../secrets"):
        assert not task_scope_allows_path(scope, path), path
    assert task_scope_allows_path(scope, "data/ok.txt")


def test_closing_a_deny_list_twice_is_the_same_deny_list():
    from agentauth.core.task_scope import close_deny_patterns

    once = close_deny_patterns(["a/**", "b/*"])
    assert close_deny_patterns(once) == once


def test_the_floor_holds_under_randomized_stress():
    """A smaller run of `benchmarks.stress_scope`, so CI exercises the floor.

    This predicate contains 100% of surface-leaving attacks across more than
    4,400 events and had never been fuzzed until the run that found the two
    defects above.
    """
    from benchmarks.stress_scope import (
        ALLOWED_PREFIXES,
        DENIED_PREFIXES,
        check,
        generate,
    )

    scope = TaskScope(allowed_paths=[f"{p}/**" for p in ALLOWED_PREFIXES],
                      denied_paths=[f"{p}/**" for p in DENIED_PREFIXES])
    rng = random.Random(5)  # noqa: S311 - reproducible sweep, not a secret
    unsafe = []
    for _ in range(30_000):
        path = generate(rng)
        for name in check(path, scope):
            if name != "conservative-refusal":
                unsafe.append(f"{name}: {path!r}")
    assert not unsafe, unsafe[:8]
