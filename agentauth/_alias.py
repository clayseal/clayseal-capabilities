"""Alias the pre-0.6 ``agentauth.*`` import paths onto ``clayseal.*``.

The package was renamed in 0.6. Deployments that installed it from the private
feed import ``agentauth.capabilities``; this keeps those imports working for one
release, and warns.

The aliased module IS the real module, not a copy. That distinction is the whole
reason this file is an import hook rather than a folder of ``from x import *``
re-exports: several modules here hold process-wide state (the plugin registry,
the used-token store, the house-rule failure counter). Two module objects would
mean two registries, and a plugin registered through the old path would be
invisible to a lookup through the new one. That failure would be silent, and in
the case of the used-token store it would be a replay window.

``agentauth`` itself stays a namespace package with no ``__init__.py``, so a
separately installed ``agentauth.identity`` still resolves alongside this.
"""
from __future__ import annotations

import importlib
import sys
import warnings
from importlib.abc import Loader, MetaPathFinder
from importlib.machinery import ModuleSpec

#: Old prefix -> new prefix. Only the two subpackages this distribution ships.
#: `agentauth.identity` and `agentauth.receipts` are separate distributions and
#: are deliberately absent: they must keep resolving normally.
_ALIASES = {
    "agentauth.capabilities": "clayseal.capabilities",
    "agentauth.core": "clayseal.core",
}

_WARNED: set[str] = set()


def _target_for(name: str) -> str | None:
    """The `clayseal.*` name for `name`, or None if it is not ours to alias."""
    for old, new in _ALIASES.items():
        if name == old:
            return new
        if name.startswith(old + "."):
            return new + name[len(old):]
    return None


def warn_once(name: str, target: str | None = None) -> None:
    """Warn once per aliased subpackage that ``name`` is the old spelling.

    Called from the finder for submodules, and directly from each shim
    ``__init__`` for the subpackage root: a plain ``from agentauth.capabilities
    import Guardrail`` resolves against a real file and never reaches the
    finder, so without that second call the most common import of all would
    deprecate silently.
    """
    parts = name.split(".")
    root = ".".join(parts[:2])
    if root not in _ALIASES or root in _WARNED:
        return
    _WARNED.add(root)
    warnings.warn(
        f"{root} was renamed to {_ALIASES[root]} in Clay Seal 0.6 and will stop "
        f"working in 0.7. Import {target or _ALIASES[root]} instead. "
        f"See https://github.com/clayseal/clayseal-capabilities/blob/main/docs/MIGRATION.md",
        DeprecationWarning,
        stacklevel=3,
    )


class _AliasLoader(Loader):
    def __init__(self, target: str) -> None:
        self._target = target

    def create_module(self, spec: ModuleSpec):
        # Import the real module and hand back that exact object, so the alias
        # and the real name share one module and therefore one set of globals.
        return importlib.import_module(self._target)

    def exec_module(self, module) -> None:
        return None


class _AliasFinder(MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        mapped = _target_for(fullname)
        if mapped is None:
            return None
        warn_once(fullname, mapped)
        spec = ModuleSpec(fullname, _AliasLoader(mapped), is_package=True)
        return spec


def install() -> None:
    """Put the finder on ``sys.meta_path``, once."""
    if any(isinstance(f, _AliasFinder) for f in sys.meta_path):
        return
    sys.meta_path.insert(0, _AliasFinder())
