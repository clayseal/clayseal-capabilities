"""Where the agent's tool calls come from.

The loop touches nothing but this Protocol, so what drives the agent is
independent of what enforces the policy. That matters for the demo's honesty:
the guest, the sentry and the broker do not know or care whether a call was
produced by a language model or a script, so the containment evidence is
identical either way.
"""
from __future__ import annotations

from typing import NamedTuple, Protocol, runtime_checkable


class ToolCall(NamedTuple):
    id: str
    tool: str
    args: dict


@runtime_checkable
class Provider(Protocol):
    name: str
    model: str

    def start(self, system: str, user: str) -> None:
        ...

    def next_calls(self) -> list[ToolCall]:
        """The next batch of calls, or [] when the agent is done."""
        ...

    def observe(self, call_id: str, text: str) -> None:
        """Feed a tool result back to the agent."""
        ...

    def final_text(self) -> str:
        ...


def build_provider(name: str, scenario, *, model: str = "") -> Provider:
    from demo.providers.mock import attack_provider, benign_provider

    if name in {"mock", "attack"}:
        return attack_provider(scenario)
    if name in {"benign", "mock-benign"}:
        return benign_provider(scenario)
    if name in {"openai", "live", "azure"}:
        from demo.providers.live import LiveProvider

        # `openai` and `azure` are explicit routes; only `live` auto-detects.
        route = {"openai": "openai", "azure": "azure"}.get(name, "auto")
        return LiveProvider(scenario, model=model, route=route)
    raise SystemExit(
        f"unknown provider {name!r} "
        "(expected: mock, benign, openai, azure, live)")
