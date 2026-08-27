"""Every test module must COLLECT without the optional extras installed.

This is the third instance of one defect in two CI runs, so it gets a test
rather than another fix.

An optional dependency imported at module scope in a test file does not produce
a skipped test. It produces a **collection error**, and pytest aborts the entire
run before any other test executes. The suite does not go from 1361 passing to
1357 passing; it goes to zero.

Both instances passed locally and failed in CI for the same reason: the dev venv
here happens to have the optional package installed and the test job does not. A
suite that is green only on the machine that wrote it is precisely what CI exists
to catch, and catching it one module at a time costs a full CI round trip each
time.

    test_biscuit_scope.py   agentauth.biscuit_scope   ([biscuit-service])
    test_env_seed.py        agentdojo, transitively   ([benchmarks])

So: parse every test module, find what it imports at module scope, and require a
guard for anything that is not a hard dependency. Reading the source rather than
importing it is deliberate, importing would need the very packages whose absence
is the case under test.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

TESTS = Path(__file__).parent
SOURCES = sorted(p for p in TESTS.glob("*.py") if p.name != Path(__file__).name)

#: Distributions that are NOT hard dependencies of `agentauth-capabilities`.
#: Every one is an optional extra in `pyproject.toml`, so a module importing one
#: at module scope must guard it.
OPTIONAL_DISTRIBUTIONS = {
    "agentdojo",       # [benchmarks]
    "biscuit_auth",    # via [biscuit-service]
    "boto3",           # [dynamodb]
    "fakeredis",       # [dev], test double
    "httpx",           # [oidc]
    "jwt",             # [oidc] / [a2a]
    "openai",          # [demo]
    "redis",           # [redis]
    "rfc8785",         # [a2a]
    "rich",            # [demo]
    "spiffe",          # [spiffe]
    "torch",           # [monitor]
}

#: First-party modules that only exist with an optional layer installed, or that
#: pull an optional distribution in transitively. The value is the set of guard
#: names that legitimately protect it, guarding the DISTRIBUTION the module
#: needs is as good as guarding the module, and often clearer about why.
OPTIONAL_FIRST_PARTY = {
    "agentauth.biscuit_scope": {"agentauth.biscuit_scope", "biscuit_auth"},
    "agentauth.identity": {"agentauth.identity", "biscuit_auth"},
    "benchmarks.live": {"benchmarks.live", "agentdojo"},
}


def _module_scope_imports(tree: ast.AST) -> set[str]:
    """Dotted names imported at module scope, not inside a function."""
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def _acceptable_guards(name: str) -> set[str] | None:
    """Guard names that would legitimately protect importing `name`."""
    root = name.split(".")[0]
    if root in OPTIONAL_DISTRIBUTIONS:
        return {root}
    for prefix, guards in OPTIONAL_FIRST_PARTY.items():
        if name == prefix or name.startswith(prefix + "."):
            return guards
    return None


def _guard_line(tree: ast.AST, guards: set[str]) -> int | None:
    """Line of the first `pytest.importorskip("<guard>")` call, or None.

    Read from the AST rather than by searching the text: the module docstring
    names these modules in prose, and a substring search finds the prose first.
    That is how the first version of this test reported a guard as being AFTER
    the import it protects, when it was the docstring it had found.
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        target = getattr(func, "attr", None) or getattr(func, "id", None)
        if target != "importorskip" or not node.args:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            if first.value in guards:
                return node.lineno
    return None


def test_there_are_modules_to_check():
    assert len(SOURCES) > 40, len(SOURCES)


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.name)
def test_module_collects_without_the_optional_extras(path: Path):
    source = path.read_text()
    tree = ast.parse(source, filename=str(path))

    unguarded: list[tuple[str, set[str]]] = []
    for imported in sorted(_module_scope_imports(tree)):
        guards = _acceptable_guards(imported)
        if guards is None:
            continue
        if _guard_line(tree, guards) is None:
            unguarded.append((imported, guards))

    assert not unguarded, (
        f"{path.name} imports {[i for i, _ in unguarded]} at module scope "
        f"without a guard. That is a COLLECTION ERROR when the extra is absent, "
        f"which aborts the entire suite rather than skipping this file. Add "
        f"`pytest.importorskip({sorted(unguarded[0][1])[0]!r}, reason=...)` "
        f"above the import."
    )


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: p.name)
def test_the_guard_comes_before_the_import_it_guards(path: Path):
    """A guard below the import it protects protects nothing.

    Both positions come from the AST, so the module docstring naming these
    packages in prose cannot be mistaken for either one.
    """
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Import):
            imported = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported = [node.module]
        else:
            continue
        for name in imported:
            guards = _acceptable_guards(name)
            if guards is None:
                continue
            guard_line = _guard_line(tree, guards)
            if guard_line is None:
                continue          # absence is the other test's business
            assert guard_line < node.lineno, (
                f"{path.name}: the guard for {name!r} is on line {guard_line}, "
                f"after the import on line {node.lineno}, so it never runs in time"
            )
