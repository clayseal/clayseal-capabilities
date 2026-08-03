"""Pluggable execution-sandbox backends.

iVisor is the first substrate that can enforce a Clay Seal envelope at the
syscall boundary, but it is macOS/Apple-Silicon-only. Resolving the backend by
name — the same shape ``default_biscuit_backend`` uses for capability tokens —
keeps that a deployment choice rather than a hard-coded dependency: a Linux
deployment can register a gVisor or seccomp backend under the same Protocol and
every caller above this line is unchanged.

Registration follows ``agentauth.core.plugins``: either an entry point in the
``agentauth.sandbox_backends`` group, or an in-process
``register_plugin("sandbox_backends", name, obj)``. A registered backend shadows
the built-in one of the same name.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, runtime_checkable

from agentauth.capabilities.sandbox.session import (
    SandboxOutcome,
    SandboxRunSpec,
    run_sandboxed,
)

PLUGIN_GROUP = "sandbox_backends"


@runtime_checkable
class SandboxBackend(Protocol):
    """An execution substrate that enforces a lowered envelope."""

    name: str

    def run(self, spec: SandboxRunSpec, **sinks) -> SandboxOutcome:
        ...


class IVisorBackend:
    """The built-in backend: iVisor as an external, launch-time-configured binary."""

    name = "ivisor"

    def run(self, spec: SandboxRunSpec, *,
            receipt_sink: Callable[[dict], None] | None = None,
            decision_log=None, compute_budget=None,
            on_event=None) -> SandboxOutcome:
        return run_sandboxed(spec, receipt_sink=receipt_sink,
                             decision_log=decision_log,
                             compute_budget=compute_budget, on_event=on_event)


def default_sandbox_backend(name: str = "ivisor") -> SandboxBackend:
    """Resolve a sandbox backend by name, preferring a registered plugin."""
    from agentauth.core.plugins import get_plugin
    try:
        return get_plugin(PLUGIN_GROUP, name)
    except KeyError:
        pass
    if name == "ivisor":
        return IVisorBackend()
    raise LookupError(
        f"no sandbox backend named {name!r}. Register one under the "
        f"'agentauth.{PLUGIN_GROUP}' entry-point group, or call "
        f"register_plugin({PLUGIN_GROUP!r}, {name!r}, backend).")
