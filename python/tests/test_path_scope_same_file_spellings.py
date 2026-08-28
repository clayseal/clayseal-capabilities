"""Spellings that open the DENIED file on a filesystem this library cannot see.

`task_scope.py` already resolves an ambiguous path against the agent: denied if
ANY reading is denied, allowed only if EVERY reading is allowed. That rule was
applied to backslashes and not to two other ambiguities:

    workspace/SECRETS/key.pem     case; macOS and Windows are case-insensitive
    workspace/secrets./key.pem    Win32 strips trailing dots
    workspace/secrets /key.pem    Win32 strips trailing spaces

All three open `workspace/secrets/key.pem`, which `denied_paths` names. All
three were ALLOWED, because `fnmatchcase` compares exactly.

The extra readings widen DENY only. Adding them to `path_readings` would also
make the ALLOW side stricter, and would then refuse paths that are genuinely
distinct files on a case-sensitive filesystem. `test_allow_is_not_narrowed`
below is what holds that line.
"""
from __future__ import annotations

import pytest

from clayseal.core.task_scope import TaskScope, task_scope_allows_path


def _scope(denied=("workspace/secrets/**",)) -> TaskScope:
    return TaskScope(
        allowed_paths=["workspace/**"],
        denied_paths=list(denied),
        allowed_actions=["read"],
        allowed_resources=["workspace"],
    )


SAME_FILE_AS_DENIED = [
    ("exact", "workspace/secrets/key.pem"),
    ("upper", "workspace/SECRETS/key.pem"),
    ("mixed", "workspace/Secrets/key.pem"),
    ("upper_file", "workspace/secrets/KEY.PEM"),
    ("trailing_dot", "workspace/secrets./key.pem"),
    ("trailing_space", "workspace/secrets /key.pem"),
    ("backslash", "workspace\\secrets\\key.pem"),
    ("traversal", "workspace/pub/../secrets/key.pem"),
]


@pytest.mark.parametrize("name,path", SAME_FILE_AS_DENIED,
                         ids=[c[0] for c in SAME_FILE_AS_DENIED])
def test_every_spelling_of_the_denied_file_is_denied(name, path):
    assert task_scope_allows_path(_scope(), path) is False, f"{name}: {path!r} allowed"


def test_the_deny_list_may_be_written_in_either_case():
    """Folding one side only would close the bypass in one direction and not the
    other, so a deny-list written in capitals has to work too."""
    upper = _scope(denied=("workspace/SECRETS/**",))
    assert task_scope_allows_path(upper, "workspace/secrets/key.pem") is False
    assert task_scope_allows_path(upper, "workspace/SECRETS/key.pem") is False


def test_allow_is_not_narrowed():
    """The readings widen DENY only.

    A path that no deny pattern names must still be allowed, including one whose
    case differs from anything in the allow-list. If these start failing, the
    extra readings have leaked into the ALLOW side and are now refusing
    legitimate work.
    """
    scope = _scope()
    for path in ["workspace/notes.txt", "workspace/Reports/Q3.csv",
                 "workspace/DATA/input.json"]:
        assert task_scope_allows_path(scope, path) is True, path


def test_a_similar_name_is_not_swept_up():
    """`secretsanta` is not `secrets`. Prefix matching rather than segment
    matching would deny it, and that would be a false denial invented by the
    fix rather than a bypass closed by it."""
    scope = _scope()
    assert task_scope_allows_path(scope, "workspace/secretsanta/list.txt") is True
    assert task_scope_allows_path(scope, "workspace/secrets-archive/old.txt") is True


def test_the_control_still_denies():
    """If the deny mechanism goes inert, every assertion above still passes
    except this one, because they all assert False."""
    assert task_scope_allows_path(_scope(), "workspace/secrets/key.pem") is False
    assert task_scope_allows_path(_scope(denied=()), "workspace/secrets/key.pem") is True
