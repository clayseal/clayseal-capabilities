"""The wheel must be importable from the wheel alone.

``pyproject.toml`` ships ``only-include = ["agentauth/capabilities"]``. Anything
the library reaches for outside that tree — the ``benchmarks`` harness, the
``demo`` package, the optional identity layer at module scope — is present in
the development checkout and absent in every real install, so the failure never
shows up here and always shows up for the integrator.

``deployable_stack.py`` did exactly this: a lazy ``from benchmarks.core.
detector_eval import _goal_for`` inside ``from_benchmark_task``. Lazy, so import
succeeded and only the call raised, and the CI layering step did not cover it —
it forbids ``agentauth.receipts``, ``agentauth.backend`` and top-level
``agentauth.identity``, and had no opinion about the harness.

This test reads the source rather than the runtime, so a lazy import inside a
function body is caught the same as a top-level one.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[2] / "agentauth" / "capabilities"

#: Top-level module names the shipped package may never depend on, at any depth.
#: `agentauth.identity` is deliberately absent: it is a real optional extra
#: (`[biscuit-service]`) and is already covered by the CI `--forbid-toplevel`
#: check, which allows it inside a function and forbids it at module scope.
FORBIDDEN_ROOTS = {"benchmarks", "demo", "examples", "scratchpad", "scripts"}

SOURCES = sorted(PACKAGE.rglob("*.py"))


def _imported_roots(tree: ast.AST) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom):
            # `level > 0` is a relative import and cannot leave the package.
            if node.level == 0 and node.module:
                roots.add(node.module.split(".", 1)[0])
    return roots


def test_there_are_sources_to_check():
    """A glob that stops matching would make every assertion below vacuous."""
    assert len(SOURCES) > 50, len(SOURCES)


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: str(p.name))
def test_module_does_not_import_anything_outside_the_wheel(path: Path):
    tree = ast.parse(path.read_text(), filename=str(path))
    leaked = _imported_roots(tree) & FORBIDDEN_ROOTS
    assert not leaked, (
        f"{path.relative_to(PACKAGE.parent.parent)} imports {sorted(leaked)}, which is "
        f"not shipped in the wheel (only-include = ['agentauth/capabilities']). "
        f"Move the dependency to the caller, or invert it."
    )
