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


#: Wall-clock ceiling for ONE completion, and for the judge as a whole. The
#: judge runs inside `SessionBroker.authorize`, under the session lock, and the
#: OpenAI SDK's default is a 600-second timeout with its own internal retries.
#: Four attempts of that is over an hour of a held lock on a code path whose only
#: possible output is a soft STEP_UP, and it is reachable by anyone who can make
#: the endpoint slow. Both numbers are overridable per deployment.
DEFAULT_REQUEST_TIMEOUT = float(os.environ.get("CLAYSEAL_JUDGE_TIMEOUT", "8"))
DEFAULT_TOTAL_BUDGET = float(os.environ.get("CLAYSEAL_JUDGE_BUDGET", "20"))


def make_chat_client(
    *, timeout: float | None = None, max_retries: int = 0
) -> tuple[Any, str] | tuple[None, str]:
    """Return ``(client, label)`` or ``(None, reason)``.

    The client is built with an explicit per-request timeout and with the SDK's
    own retry loop DISABLED, because the judge has its own bounded one and two
    nested retry loops multiply into the wait this exists to prevent.
    """
    timeout = DEFAULT_REQUEST_TIMEOUT if timeout is None else timeout
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
                azure_endpoint=az_ep, api_key=az_key, api_version=api_version,
                timeout=timeout, max_retries=max_retries)
            return client, f"azure:{model}"
        key = load_openai_api_key()
        if not key:
            return None, "no OPENAI_API_KEY / ~/.openai_api_key / Azure config"
        from openai import OpenAI
        return OpenAI(api_key=key, timeout=timeout, max_retries=max_retries), model
    except Exception as exc:  # noqa: BLE001 - absent credentials are not an error
        # Returns a REASON rather than raising: the entailment judge is optional
        # and every caller treats "no client" as "run without the advisory".
        return None, f"client init failed: {type(exc).__name__}"


def default_entailment_judge(*, budget_seconds: float | None = None):
    """Build ``llm_entailment_judge`` when credentials exist; else ``None``."""
    from agentauth.capabilities.monitor.entailment import llm_entailment_judge

    client, label = make_chat_client()
    if client is None:
        return None
    model = label.split(":", 1)[-1] if label.startswith("azure:") else label
    return llm_entailment_judge(client, model, budget_seconds=budget_seconds)


def bounded(judge, *, budget_seconds: float | None = None):
    """Wrap any judge so it cannot exceed ``budget_seconds`` of wall clock.

    The timeouts above bound a WELL-BEHAVED client. This bounds the rest: a
    caller-supplied judge, a hung socket the SDK does not notice, a local model
    that blocks. The worker thread is left running and abandoned rather than
    joined, because the caller is holding the session lock and the whole purpose
    of this wrapper is to give the lock back on schedule.

    An expired budget returns no reasons, which is the same fail-open the judge
    already has for API errors, and is safe for the same reason: this tier can
    only ever ESCALATE, so losing it forfeits an advisory rather than a control.
    """
    if judge is None:
        return None
    budget = DEFAULT_TOTAL_BUDGET if budget_seconds is None else budget_seconds

    def run(goal: str, samples: list[dict[str, str]]) -> list[str]:
        from concurrent.futures import ThreadPoolExecutor
        from concurrent.futures import TimeoutError as FuturesTimeout

        pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="clayseal-judge")
        try:
            future = pool.submit(judge, goal, samples)
            try:
                return list(future.result(timeout=budget) or ())
            except FuturesTimeout:
                return []
            except Exception:  # noqa: BLE001 - fail open, same as the judge itself
                return []
        finally:
            pool.shutdown(wait=False)

    return run
