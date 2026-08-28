"""Pluggable L2 capability layers for receipts and framework integration."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from clayseal.capabilities.commit import issue_commit_token, verify_commit_token
from clayseal.capabilities.task_scope import compile_task_scope
from clayseal.core.identity_protocol import CapabilityLayer

# `CapabilityLayer` is the L3-facing Protocol and was referenced by three
# annotations here without ever being imported. `from __future__ import
# annotations` made every annotation a string, so the module imported fine and
# the name simply did not resolve, `get_type_hints`, any type checker and any
# reader following the annotation all hit a NameError instead.


@dataclass
class AgentAuthCapabilityLayer:
    name: str = "agentauth"

    def issue_commit_token(self, ctx: Any, *, key: Any, ttl_seconds: int) -> Any:
        return issue_commit_token(ctx, key=key, ttl_seconds=ttl_seconds)

    def verify_commit_token(
        self, signed: Any, *, ctx: Any, trusted_minting_keys: Any = None
    ) -> tuple[bool, str | None]:
        return verify_commit_token(
            signed, ctx=ctx, trusted_minting_keys=trusted_minting_keys
        )

    def compile_task_scope(self, mandate: dict[str, Any]) -> Any:
        return compile_task_scope(mandate)


default_capability_layer = AgentAuthCapabilityLayer()

_LAYERS: dict[str, CapabilityLayer] = {default_capability_layer.name: default_capability_layer}


def register_capability_layer(layer: CapabilityLayer) -> None:
    _LAYERS[layer.name] = layer


def get_capability_layer(name: str = "agentauth") -> CapabilityLayer:
    if name not in _LAYERS:
        raise KeyError(f"unknown capability layer {name!r}; known: {', '.join(sorted(_LAYERS))}")
    return _LAYERS[name]


def list_capability_layers() -> list[str]:
    return sorted(_LAYERS)
