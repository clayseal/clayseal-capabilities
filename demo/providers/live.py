"""A real language model driving the agent.

`configure_provider` is a copy of `benchmarks/live/run_agentdojo.py:19-65` rather
than an import: that module pulls in the AgentDojo stack at import time, which
caps Python at 3.12 and drags a large dependency into a demo that needs neither.
The function itself depends only on `openai` and `os`.

BE HONEST ABOUT WHAT A LIVE RUN PROVES. A model may simply decline the injected
instruction, in which case the safety expectations hold without ever being
stressed and `escalates to CONTAINED` correctly reads "not yet". That is a real
outcome worth showing, not a failure to hide, but it is why CI never gates on a
live run and why the scripted provider is the better containment proof.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from demo.providers import ToolCall

_REAL_OPENAI = None


def configure_provider(model: str, *, route: str = "auto") -> str:
    """Point `openai.OpenAI` at Azure or public OpenAI.

    `route` is explicit on purpose. Auto-detection has a trap: the inherited
    default for AZURE_OPENAI_DEPLOYMENTS is the same model id as the demo's
    default `--model`, so a shell that still has Azure variables exported from a
    benchmark run would silently route `--provider openai` to Azure and fail
    with an auth error that looks like the agent doing nothing. `--provider
    openai` now means public OpenAI, full stop.
    """
    global _REAL_OPENAI
    try:
        import openai
    except ImportError as exc:
        # Not a base dependency of this package, only the live provider needs
        # it, and a venv built for the library alone will not have it.
        raise RuntimeError(
            "the live provider needs the openai package: pip install openai. "
            "(--provider mock needs no model and no key.)") from exc

    if _REAL_OPENAI is None:
        _REAL_OPENAI = openai.OpenAI

    az_ep = os.environ.get("AZURE_OPENAI_ENDPOINT")
    az_key = (os.environ.get("AZURE_OPENAI_KEY")
              or os.environ.get("AZURE_OPENAI_API_KEY"))
    az_models = {m for m in os.environ.get(
        "AZURE_OPENAI_DEPLOYMENTS", "gpt-4o-mini-2024-07-18").split(",") if m}
    has_openai = bool(os.environ.get("OPENAI_API_KEY"))

    if route == "openai":
        if not has_openai:
            raise RuntimeError(
                "--provider openai needs OPENAI_API_KEY. Export it, or use "
                "--provider azure with AZURE_OPENAI_ENDPOINT and "
                "AZURE_OPENAI_KEY.")
        use_azure = False
    elif route == "azure":
        if not (az_ep and az_key):
            raise RuntimeError(
                "--provider azure needs AZURE_OPENAI_ENDPOINT and "
                "AZURE_OPENAI_KEY (or AZURE_OPENAI_API_KEY).")
        use_azure = True
    else:
        use_azure = bool(az_ep and az_key) and (model in az_models
                                                or not has_openai)
        if not use_azure and not has_openai:
            raise RuntimeError(
                "no model credentials found: set OPENAI_API_KEY, or "
                "AZURE_OPENAI_ENDPOINT + AZURE_OPENAI_KEY.")

    if use_azure:
        from openai import AzureOpenAI
        api_version = os.environ.get("AZURE_OPENAI_API_VERSION",
                                     "2024-12-01-preview")

        def _factory(*_a, **_k):
            client = AzureOpenAI(azure_endpoint=az_ep, api_key=az_key,
                                 api_version=api_version)
            original = client.chat.completions.create

            def _create(*a, **k):
                if k.get("temperature") == 0:   # gpt-5 accepts only the default
                    k.pop("temperature")
                return original(*a, **k)

            client.chat.completions.create = _create
            return client

        openai.OpenAI = _factory
        return f"azure:{az_ep} ({model})"

    openai.OpenAI = _REAL_OPENAI
    return f"openai ({model})"


@dataclass
class LiveProvider:
    """An OpenAI tool-use loop, shaped to the demo's Provider protocol."""

    scenario: object
    model: str = "gpt-4o-mini-2024-07-18"
    name: str = "openai"
    route: str = "auto"
    _messages: list[dict] = field(default_factory=list, init=False)
    _client: object | None = field(default=None, init=False)
    _final: str = field(default="", init=False)
    _turns: int = field(default=0, init=False)

    def start(self, system: str, user: str) -> None:
        self.name = configure_provider(self.model, route=self.route)
        from openai import OpenAI

        self._client = OpenAI()
        self._messages = [{"role": "system", "content": system},
                          {"role": "user", "content": user}]

    def next_calls(self) -> list[ToolCall]:
        response = self._client.chat.completions.create(
            model=self.model, messages=self._messages,
            tools=self.scenario.tools, tool_choice="auto")
        message = response.choices[0].message
        self._turns += 1
        if not message.tool_calls:
            self._final = message.content or ""
            if self._turns == 1:
                # Distinguishable from a model that worked and then stopped.
                # A first turn with no tool call means the run produced no
                # evidence at all, and the summary must not read as containment.
                self._final = ("[the model made no tool call on its first turn] "
                               + self._final)
            return []

        self._messages.append({
            "role": "assistant", "content": message.content or "",
            "tool_calls": [tc.model_dump() for tc in message.tool_calls]})

        calls = []
        for tc in message.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            calls.append(ToolCall(id=tc.id, tool=tc.function.name, args=args))
        return calls

    def observe(self, call_id: str, text: str) -> None:
        self._messages.append({"role": "tool", "tool_call_id": call_id,
                               "content": text})

    def final_text(self) -> str:
        return self._final
