"""Shared OpenAI / Azure OpenAI client helpers for advisory judges.

Keys are never logged. Resolution order:

1. ``AZURE_OPENAI_ENDPOINT`` + ``AZURE_OPENAI_KEY`` / ``AZURE_OPENAI_API_KEY``
2. ``OPENAI_API_KEY``
3. ``~/.openai_api_key`` (first line)
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def load_openai_api_key() -> str:
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if key:
        return key
    for path in (
        Path.home() / ".openai_api_key",
        Path.home() / ".config" / "openai_api_key",
    ):
        try:
            text = path.read_text().strip()
            if text:
                return text.splitlines()[0].strip()
        except OSError:
            continue
    return ""


def make_chat_client() -> tuple[Any, str] | tuple[None, str]:
    """Return ``(client, label)`` or ``(None, reason)``."""
    model = os.environ.get("CLAYSEAL_ENTAILMENT_MODEL") or os.environ.get(
        "OPENAI_MODEL", "gpt-4o")
    az_ep = os.environ.get("AZURE_OPENAI_ENDPOINT", "").strip()
    az_key = (os.environ.get("AZURE_OPENAI_KEY")
              or os.environ.get("AZURE_OPENAI_API_KEY") or "").strip()
    try:
        if az_ep and az_key:
            from openai import AzureOpenAI
            api_version = os.environ.get(
                "AZURE_OPENAI_API_VERSION", "2024-12-01-preview")
            client = AzureOpenAI(
                azure_endpoint=az_ep, api_key=az_key, api_version=api_version)
            return client, f"azure:{model}"
        key = load_openai_api_key()
        if not key:
            return None, "no OPENAI_API_KEY / ~/.openai_api_key / Azure config"
        from openai import OpenAI
        return OpenAI(api_key=key), model
    except Exception as exc:  # noqa: BLE001 - absent credentials are not an error
        # Returns a REASON rather than raising: the entailment judge is optional
        # and every caller treats "no client" as "run without the advisory".
        return None, f"client init failed: {type(exc).__name__}"


def default_entailment_judge():
    """Build ``llm_entailment_judge`` when credentials exist; else ``None``."""
    from agentauth.capabilities.monitor.entailment import llm_entailment_judge

    client, label = make_chat_client()
    if client is None:
        return None
    model = label.split(":", 1)[-1] if label.startswith("azure:") else label
    return llm_entailment_judge(client, model)
