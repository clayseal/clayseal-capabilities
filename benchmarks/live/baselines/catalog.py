"""Shared catalog, taint tokens, JSON parse, and disk cache for original gates."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

CACHE_PATH = (
    Path(__file__).resolve().parents[2] / "results" / ".original_gates_cache.json"
)

_TOKEN = re.compile(r"[A-Za-z0-9_.:@/+-]{3,}")
_EDGE = ".:,;!?/+-_@"
_MONEY = re.compile(r"\$?\d{1,3}(?:,\d{3})+(?:\.\d+)?|\$\d+(?:\.\d+)?|\b\d+(?:\.\d+)?\b")
_OBSERVE = re.compile(
    r"^(list_|read_|get_|search_|load_|fetch_|check_|lookup_|find_|query_)",
    re.IGNORECASE,
)

_cache: dict[str, Any] | None = None


def load_cache() -> dict[str, Any]:
    global _cache
    if _cache is None:
        try:
            _cache = json.loads(CACHE_PATH.read_text())
        except (OSError, ValueError):
            _cache = {}
    return _cache


def save_cache() -> None:
    if _cache is None:
        return
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps(_cache, indent=0, sort_keys=True))


def cache_key(kind: str, user_prompt: str, tools: list[dict]) -> str:
    blob = json.dumps(
        {"kind": kind, "q": user_prompt, "tools": tool_catalog(tools)},
        sort_keys=True, separators=(",", ":"),
    )
    return kind + ":" + hashlib.sha256(blob.encode()).hexdigest()


def cached(kind: str, user_prompt: str, tools: list[dict]) -> Any | None:
    return load_cache().get(cache_key(kind, user_prompt, tools))


def store(kind: str, user_prompt: str, tools: list[dict], spec: Any) -> None:
    load_cache()[cache_key(kind, user_prompt, tools)] = spec
    save_cache()


def tool_catalog(tools: list[dict]) -> list[dict[str, Any]]:
    """OpenAI tool schemas → Progent/DRIFT `{name, description, args}` list."""
    out: list[dict[str, Any]] = []
    for t in tools:
        fn = t.get("function") or t
        name = fn.get("name")
        if not name:
            continue
        params = fn.get("parameters") or {}
        props = params.get("properties") or {}
        args = {k: (v if isinstance(v, dict) else {"description": str(v)})
                for k, v in props.items()}
        out.append({
            "name": str(name),
            "description": str(fn.get("description") or ""),
            "args": args,
        })
    return out


def tool_names(tools: list[dict]) -> list[str]:
    return [c["name"] for c in tool_catalog(tools)]


def is_observe(tool: str) -> bool:
    return bool(_OBSERVE.match(tool))


def norm(s: str) -> str:
    return str(s).lower().replace(",", "").replace("$", "").replace(" ", "")


def tokens(value: Any) -> set[str]:
    out: set[str] = set()
    if value is None:
        return out
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        out.add(norm(str(value)))
        out.add(norm(f"{value:g}"))
        return out
    if isinstance(value, (list, tuple)):
        for v in value:
            out |= tokens(v)
        return out
    if isinstance(value, dict):
        for v in value.values():
            out |= tokens(v)
        return out
    text = str(value)
    for m in _TOKEN.finditer(text):
        tok = m.group(0).strip(_EDGE)
        if len(tok) >= 3:
            out.add(norm(tok))
    for m in _MONEY.finditer(text):
        out.add(norm(m.group(0)))
    out.add(norm(text))
    return {t for t in out if t}


def same_value(got: Any, expected: Any) -> bool:
    if isinstance(got, bool) or isinstance(expected, bool):
        return got is expected
    if got == expected:
        return True
    if isinstance(got, (int, float)) and isinstance(expected, (int, float)):
        return float(got) == float(expected)
    return str(got).strip().lower() == str(expected).strip().lower()


def parse_json(text: str) -> Any:
    text = (text or "").strip()
    if not text:
        raise ValueError("empty model response")
    block = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL)
    if block:
        text = block.group(1).strip()
    last: Exception | None = None
    for candidate in _json_candidates(text):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError as exc:
            last = exc
    start_obj, start_arr = text.find("{"), text.find("[")
    starts = [i for i in (start_obj, start_arr) if i >= 0]
    if starts:
        start = min(starts)
        # Walk the brackets once and try only the balanced end points, instead
        # of every suffix. The old loop was `for end in range(len(text), start,
        # -1)` with a `json.loads` inside, so an unparseable response cost
        # O(n^2) work in the C parser: quadratic in the length of a string a
        # model produced. There are at most as many balanced ends as there are
        # closing brackets, and the JSON we want ends at one of them.
        opener = text[start]
        closer = {"{": "}", "[": "]"}[opener]
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == opener:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
    if last is not None:
        raise last
    raise ValueError("empty model response")


def _json_candidates(text: str) -> list[str]:
    out = [text]
    trimmed = re.sub(r",\s*([}\]])", r"\1", text)
    if trimmed != text:
        out.append(trimmed)
    start_obj, start_arr = text.find("{"), text.find("[")
    starts = [i for i in (start_obj, start_arr) if i >= 0]
    if starts:
        start = min(starts)
        blob = text[start:]
        if blob not in out:
            out.append(blob)
        out.append(re.sub(r",\s*([}\]])", r"\1", blob))
    return out


def ask_json(system: str, payload: str) -> Any:
    from benchmarks.openai_ask import ask
    return parse_json(ask(system, payload, max_tokens=3500))


def compile_spec(kind: str, user_prompt: str, tools: list[dict],
                 system: str, payload: str) -> Any:
    hit = cached(kind, user_prompt, tools)
    if hit is not None:
        return hit
    last: Exception | None = None
    request = payload
    for attempt in range(3):
        try:
            spec = ask_json(system, request)
            store(kind, user_prompt, tools, spec)
            return spec
        except (ValueError, json.JSONDecodeError) as exc:
            last = exc
            request = (
                payload
                + "\nReturn a single valid JSON object. "
                + f"Attempt {attempt + 2}: the previous output failed to parse."
            )
    raise last or ValueError(f"{kind} compile returned no JSON")
