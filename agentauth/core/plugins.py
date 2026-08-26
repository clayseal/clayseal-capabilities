"""Shared plugin registry — the discovery mechanism behind every Clay Seal seam.

Each swappable seam (identity providers, capability-token backends, policy engines,
receipt exporters, approval backends, attestation verifiers) is a named *group*. A
plugin is any object registered under ``(group, name)``. Resolution checks, in order:

1. objects registered in-process via :func:`register_plugin`, then
2. entry points advertised by installed distributions under the group
   ``agentauth.<group>`` (so a third-party package adds a provider by declaring an
   entry point — no edits to the layer that consumes it).

This keeps the layers decoupled: a consumer asks for ``get_plugin("identity_providers",
"oidc")`` without importing whatever package implements it.
"""
from __future__ import annotations

from typing import Any

# group -> {name -> object}
_REGISTRY: dict[str, dict[str, Any]] = {}
# groups whose entry points have already been scanned (scan once, lazily)
_ENTRYPOINTS_LOADED: set[str] = set()
_LOG = __import__("logging").getLogger(__name__)
_PRODUCTION_ENVS = frozenset({"production", "prod"})


def _deployment_is_production() -> bool:
    import os

    for name in ("AGENTAUTH_ENV", "AGENT_RECEIPTS_ENV"):
        if os.environ.get(name, "").strip().lower() in _PRODUCTION_ENVS:
            return True
    return False


def register_plugin(group: str, name: str, obj: Any) -> None:
    """Register ``obj`` under ``(group, name)`` (in-process; wins over entry points)."""
    _REGISTRY.setdefault(group, {})[name] = obj


def get_plugin(group: str, name: str) -> Any:
    """Return the plugin registered as ``(group, name)``.

    Raises ``KeyError`` if no in-process registration or entry point provides it.
    """
    registered = _REGISTRY.get(group, {})
    if name in registered:
        return registered[name]
    _load_entry_points(group)
    registered = _REGISTRY.get(group, {})
    if name in registered:
        return registered[name]
    raise KeyError(f"no plugin {name!r} in group {group!r}")


def list_plugins(group: str) -> list[str]:
    """List all plugin names in ``group`` (in-process + entry points), sorted."""
    _load_entry_points(group)
    return sorted(_REGISTRY.get(group, {}))


def _load_entry_points(group: str) -> None:
    if group in _ENTRYPOINTS_LOADED:
        return
    _ENTRYPOINTS_LOADED.add(group)
    from importlib.metadata import entry_points

    try:
        eps = entry_points(group=f"agentauth.{group}")
    except TypeError:  # pragma: no cover - Python <3.10 selection API
        eps = entry_points().get(f"agentauth.{group}", [])
    for ep in eps:
        # In-process registrations take precedence; don't clobber them.
        if ep.name in _REGISTRY.get(group, {}):
            continue
        try:
            register_plugin(group, ep.name, ep.load())
        except Exception as exc:  # pragma: no cover - a broken third-party plugin must not
            _LOG.warning(
                "failed to load plugin %r in group %r: %s",
                ep.name,
                group,
                exc,
            )
            if _deployment_is_production():
                raise RuntimeError(
                    f"plugin {ep.name!r} in group {group!r} failed to load in production"
                ) from exc
