"""A shipped module says what it is for, at the top of the file.

32 of 171 modules had no module docstring, and they clustered: 23 were the whole
of `clayseal/capabilities/scoping/`, and the rest were core contracts —
`hash_util`, `delegation`, `decision`, `runtime`, and `commit.py`, which handles
commit tokens. A reader landing in one of those had the code and nothing about
why it exists or what it must not do.

That is a real gap for a library whose comments are the measurement record
everywhere else. It also mattered more than usual here: the subpackage without
docstrings is the one that decides how much of a repository a session may read.

The bar this enforces is presence, not quality; a rule cannot check whether a
docstring is any good. It can stop the next module arriving without one.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SHIPPED = [p for pkg in ("clayseal", "agentauth")
           for p in sorted((ROOT / pkg).rglob("*.py"))]

#: A docstring shorter than this is a label, not an explanation. Deliberately
#: low: the point is to catch `"""utils."""`, not to grade prose.
MIN_DOCSTRING_CHARS = 40


def _relative(path: pathlib.Path) -> str:
    return str(path.relative_to(ROOT))


def test_there_are_shipped_sources_to_check():
    """The control.

    Every assertion below passes over an empty list. This is the one that fails
    if the glob stops finding the package, which is how a docstring rule quietly
    stops being a rule.
    """
    assert len(SHIPPED) > 150, f"only found {len(SHIPPED)} shipped modules"


@pytest.mark.parametrize("path", SHIPPED, ids=_relative)
def test_every_module_has_a_docstring(path: pathlib.Path):
    tree = ast.parse(path.read_text())
    doc = ast.get_docstring(tree)
    assert doc, f"{_relative(path)} has no module docstring"


@pytest.mark.parametrize("path", SHIPPED, ids=_relative)
def test_the_docstring_says_something(path: pathlib.Path):
    doc = ast.get_docstring(ast.parse(path.read_text())) or ""
    assert len(doc.strip()) >= MIN_DOCSTRING_CHARS, (
        f"{_relative(path)}: {doc.strip()!r} is a label rather than an "
        "explanation of what the module is for")
