"""The wheel must be importable from the wheel alone.

``pyproject.toml`` ships
``only-include = ["agentauth/capabilities", "agentauth/core"]``. Anything the
library reaches for outside those trees, the ``benchmarks`` harness, the
``demo`` package, the optional identity layer at module scope, is present in
the development checkout and absent in every real install, so the failure never
shows up here and always shows up for the integrator.

``deployable_stack.py`` did exactly this: a lazy ``from benchmarks.core.
detector_eval import _goal_for`` inside ``from_benchmark_task``. Lazy, so import
succeeded and only the call raised, and the CI layering step did not cover it
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
#: `agentauth.identity` is handled separately below: it is a real optional extra
#: (`[biscuit-service]`), so it is allowed inside a function and forbidden at
#: module scope.
FORBIDDEN_ROOTS = {"benchmarks", "demo", "examples", "scratchpad", "scripts"}

#: Optional sibling layers. Importing one at MODULE SCOPE makes an optional
#: extra mandatory: the package stops importing for anyone who did not install
#: it, which is the whole point of it being an extra.
OPTIONAL_SIBLINGS = ("agentauth.identity", "agentauth.receipts", "agentauth.backend")

CORE = PACKAGE.parent / "core"

SOURCES = sorted(PACKAGE.rglob("*.py"))
CORE_SOURCES = sorted(CORE.rglob("*.py"))


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
        f"not shipped in the wheel. Move the dependency to the caller, or "
        f"invert it."
    )


def test_there_are_core_sources_to_check():
    assert len(CORE_SOURCES) > 15, len(CORE_SOURCES)


@pytest.mark.parametrize("path", CORE_SOURCES, ids=lambda p: f"core/{p.name}")
def test_core_does_not_import_the_layer_above_it(path: Path):
    """`agentauth.core` is the bottom of the stack and has to stay there.

    It was a separate distribution, so this was enforced by the fact that the
    package it would have imported was not installed. Vendoring it into this
    repository removes that enforcement: `agentauth.capabilities` is now one
    directory away, and an import in the wrong direction would build cleanly, run
    cleanly, and make the two impossible to separate again.
    """
    tree = ast.parse(path.read_text(), filename=str(path))
    offenders = {
        name for name in _dotted_imports(tree)
        if name.startswith("agentauth.capabilities")
    }
    assert not offenders, (
        f"agentauth/core/{path.name} imports {sorted(offenders)}. Core is the "
        f"contracts layer and nothing in it may depend on the layer above."
    )
    leaked = _imported_roots(tree) & FORBIDDEN_ROOTS
    assert not leaked, f"agentauth/core/{path.name} imports {sorted(leaked)}"


def _dotted_imports(tree: ast.AST) -> set[str]:
    """Full dotted module names, at any depth, from both import forms."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
    return names


def _module_level_imports(tree: ast.AST) -> set[str]:
    """Modules imported at module scope, not inside a function or method.

    The distinction is the contract for an optional extra: a lazy import inside
    `default_biscuit_backend()` is correct and an import at the top of the file
    is not, because the second one runs for every user whether they installed the
    extra or not.
    """
    names: set[str] = set()
    for node in tree.body:                     # top level only, by construction
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
        elif isinstance(node, ast.If):         # `if TYPE_CHECKING:` blocks
            for inner in ast.walk(node):
                if isinstance(inner, ast.Import):
                    names |= {a.name for a in inner.names}
                elif isinstance(inner, ast.ImportFrom) and inner.module:
                    names.add(inner.module)
    return names


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: str(p.name))
def test_optional_layers_are_imported_lazily(path: Path):
    """An optional extra imported at module scope is not optional.

    This replaces the CI step `python -m agentauth.core.layering ...`, which
    referenced a module that does not exist in `agentauth-core` at all, a dead
    reference left by the repo split, and one that could only be discovered by
    CI actually running, which it had never done.
    """
    tree = ast.parse(path.read_text(), filename=str(path))
    top = _module_level_imports(tree)
    leaked = sorted(
        name for name in top
        if any(name == sib or name.startswith(sib + ".") for sib in OPTIONAL_SIBLINGS)
    )
    assert not leaked, (
        f"{path.name} imports {leaked} at module scope. These are optional "
        f"extras; import them inside the function that needs them so the "
        f"package still imports without them."
    )


def test_the_optional_layer_is_actually_used_somewhere_lazily():
    """Guard the guard: if nothing imports identity at all, the test above is
    vacuous and would keep passing after the seam was deleted."""
    lazy = [
        p for p in SOURCES
        if "agentauth.identity" in p.read_text()
        and "agentauth.identity" not in _module_level_imports(
            ast.parse(p.read_text(), filename=str(p))
        )
    ]
    assert lazy, "no module imports the identity layer lazily; has the seam gone?"
