"""A path the gateway cannot resolve cannot be shown to be in scope.

`rm -rf "$OUTPUT_DIR/$EXP_DIR"` is authorized against the literal string and
executed against whatever the shell decides, so with either variable unset the
parent directory goes. The scope check already says "allowed only if EVERY
reading is allowed"; an unexpanded expansion stands for an unbounded set of
readings, so it cannot satisfy that and is refused.

Found as the single remaining structurally separable miss on SLEIGHT-Bench, and
measured to cost nothing: across seven corpora, 20,299 benign events carry no
such path.
"""

from __future__ import annotations

import pytest

from clayseal.core.task_scope import (
    TaskScope,
    path_is_indeterminate,
    path_readings,
    task_scope_allows_path,
)

WORKSPACE = TaskScope(allowed_paths=["/srv/exp/**"])


@pytest.mark.parametrize("path", [
    "/srv/exp/$OUTPUT_DIR/run",
    "/srv/exp/${OUTPUT_DIR}/run",
    "/srv/exp/$(date +%s)/run",
    "/srv/exp/`hostname`/run",
    "/srv/exp/%TEMP%/run",
])
def test_an_unresolved_expansion_is_not_in_scope(path: str) -> None:
    assert path_is_indeterminate(path)
    assert not task_scope_allows_path(WORKSPACE, path)


@pytest.mark.parametrize("path", [
    "/srv/exp/run-42/out",
    "/srv/exp/nested/deep/file.txt",
    "/srv/exp/cost-100usd.txt",
])
def test_ordinary_paths_under_the_same_scope_still_pass(path: str) -> None:
    """Control: without this, a blanket deny would pass every test above."""
    assert not path_is_indeterminate(path)
    assert task_scope_allows_path(WORKSPACE, path)


def test_the_rule_is_what_refuses_it_not_the_prefix() -> None:
    """Control: the literal form of the very same path is allowed.

    If the expansion were merely landing outside the allow-list, this would
    fail too and the test above would be proving nothing about the mechanism.
    """
    assert task_scope_allows_path(WORKSPACE, "/srv/exp/EXPANDED/run")
    assert not task_scope_allows_path(WORKSPACE, "/srv/exp/$EXP_DIR/run")


def test_it_adds_a_reading_rather_than_replacing_them() -> None:
    """The literal string must survive, or the DENY side loses its match."""
    readings = path_readings("/srv/exp/$EXP_DIR/run")
    assert "/srv/exp/$EXP_DIR/run" in readings
    assert len(readings) > 1


def test_the_deny_side_is_unaffected() -> None:
    """Widening ALLOW must not quietly narrow DENY.

    A denied pattern still has to match the literal reading; the sentinel is
    not a real path and must not become a way to escape a deny-list.
    """
    scope = TaskScope(allowed_paths=["/srv/**"], denied_paths=["/srv/secrets/**"])
    assert not task_scope_allows_path(scope, "/srv/secrets/$KEY/id_rsa")
    assert not task_scope_allows_path(scope, "/srv/secrets/id_rsa")


def test_an_unrestricted_scope_is_unchanged() -> None:
    """No allow-list means nothing to prove membership in; behaviour is as before."""
    assert task_scope_allows_path(TaskScope(), "/anywhere/$VAR/x")
