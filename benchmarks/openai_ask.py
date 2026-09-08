"""Seal-time compile client. Azure first, then OpenAI.

Keys are never logged. Cache is content-addressed so a rerun does not re-spend.
Quota exhaustion is not retried. Transient 429s are.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import time
import urllib.error
import urllib.request

from benchmarks._http import post_json

CACHE = pathlib.Path(__file__).resolve().parent / "results" / ".binder_compile_cache.json"
API_VERSION = "2024-10-21"

_cache: dict[str, str] | None = None
_stats = {"hit": 0, "miss": 0, "retry": 0}


def _openai_key() -> str:
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if key:
        return key
    for path in (
        pathlib.Path.home() / ".openai_api_key",
        pathlib.Path.home() / ".config" / "openai_api_key",
    ):
        try:
            text = path.read_text().strip()
        except OSError:
            continue
        if text:
            return text.splitlines()[0].strip()
    return ""


def _azure() -> tuple[str, str]:
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "").rstrip("/")
    key = os.environ.get("AZURE_OPENAI_KEY") or os.environ.get(
        "AZURE_OPENAI_API_KEY", "")
    return endpoint, key


def _model() -> str:
    return os.environ.get("CLAYSEAL_COMPILE_MODEL") or os.environ.get(
        "CLAYSEAL_MONITOR_DEPLOYMENT", "gpt-4.1")


def _load() -> dict[str, str]:
    global _cache
    if _cache is None:
        try:
            _cache = json.loads(CACHE.read_text())
        except (OSError, ValueError):
            _cache = {}
    return _cache


def flush() -> None:
    if _cache is not None:
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        CACHE.write_text(json.dumps(_cache, indent=0, sort_keys=True))


def stats() -> dict[str, int]:
    return dict(_stats)


def _retry_after(exc: urllib.error.HTTPError, attempt: int, body: str) -> float | None:
    """Seconds to wait, or None to give up."""
    if "insufficient_quota" in body or "credit_balance" in body:
        return None
    raw = exc.headers.get("Retry-After") if exc.headers else None
    if raw:
        try:
            return min(90.0, float(raw))
        except ValueError:
            pass
    return min(90.0, 5.0 * (2.0 ** attempt))


def ask(system: str, payload: str, *, model: str | None = None,
        max_tokens: int = 2500) -> str:
    model = model or _model()
    endpoint, azure_key = _azure()
    want_azure = os.environ.get("CLAYSEAL_MONITOR_PROVIDER", "").strip().lower() == "azure"
    if want_azure and not (endpoint and azure_key):
        raise RuntimeError(
            "CLAYSEAL_MONITOR_PROVIDER=azure but AZURE_OPENAI_ENDPOINT/KEY "
            "are unset. Refusing to fall back to public OpenAI.")
    provider = "azure" if endpoint and azure_key else "openai"
    digest = hashlib.sha256(
        (provider + "\x00" + model + "\x00" + system + "\x00" + payload
         ).encode()).hexdigest()
    cache = _load()
    if digest in cache:
        _stats["hit"] += 1
        return cache[digest]

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": payload},
    ]
    if provider == "azure":
        if not endpoint.startswith("https://"):
            raise RuntimeError("AZURE_OPENAI_ENDPOINT must be https")
        url = (f"{endpoint}/openai/deployments/{model}"
               f"/chat/completions?api-version={API_VERSION}")
        body = json.dumps({
            "messages": messages,
            "temperature": 0,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }).encode()
        headers = {"api-key": azure_key, "Content-Type": "application/json"}
    else:
        key = _openai_key()
        if not key:
            raise RuntimeError(
                "compile ask needs Azure (AZURE_OPENAI_ENDPOINT + KEY) or "
                "OPENAI_API_KEY / ~/.openai_api_key")
        url = "https://api.openai.com/v1/chat/completions"
        body = json.dumps({
            "model": model,
            "messages": messages,
            "temperature": 0,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }).encode()
        headers = {"Authorization": f"Bearer {key}",
                   "Content-Type": "application/json"}

    last: Exception | None = None
    for attempt in range(8):
        try:
            with post_json(url, data=body, headers=headers, timeout=180) as resp:
                text = json.load(resp)["choices"][0]["message"]["content"]
            cache[digest] = text
            _stats["miss"] += 1
            flush()
            return text
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode(errors="replace")
            last = RuntimeError(
                f"compile HTTP {exc.code}: {err_body[:300]}")
            delay = _retry_after(exc, attempt, err_body) if exc.code in (
                429, 500, 502, 503) else None
            if delay is not None and attempt < 7:
                _stats["retry"] += 1
                time.sleep(delay)
                continue
            raise last from exc
        except TimeoutError as exc:
            last = exc
            if attempt < 7:
                _stats["retry"] += 1
                time.sleep(min(90.0, 5.0 * (2.0 ** attempt)))
                continue
            raise
    raise last or RuntimeError("compile ask failed")
