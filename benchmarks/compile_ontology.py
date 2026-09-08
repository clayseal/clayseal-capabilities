"""Compile a tool ontology once per catalogue, then enforce it deterministically.

    python -m benchmarks.compile_ontology --limit 8
    python -m benchmarks.compile_ontology            # whole suite, cached

## The deployment problem this solves

Every general mechanism priced in `generalizing_derivation.md` needed structure
somebody has to write: a declared ontology, or structured intent. Asking an
operator to supply that PER PROMPT is not a product, it is a form.

The structure is not per prompt. It is per CATALOGUE. An enterprise's tools change
weekly; its prompts change constantly. So the split is:

    compile time, once per catalogue   derive preconditions, effects and
                                       reversibility for each tool. Reviewable,
                                       diffable, signable, versioned with the
                                       tool schema it describes.
    decision time, every call          pure deterministic checking against that
                                       artifact. No model, no network, no
                                       nondeterminism, microseconds.

This is how policy compilers already work, and `policy_draft.py` states the same
pattern for written business rules: generate a draft, have a person review it,
then enforce the reviewed thing.

## What the compiler is allowed to see

**The tool schema only.** Name, description, parameters. Never the goal, never a
trajectory, never a violation predicate, never an attack. A compiler that reads
the goal would be per-prompt again, and one that reads outcomes would be reading
the answer key. This is asserted in code below, not merely promised.

Using a model here is not the thing the provenance rule forbids. The rule is
about what may WIDEN authority at decision time from attacker-influenceable
input. A compile-time artifact that a human reviews and signs is configuration,
and it is the same trust tier as the tool schema it was derived from.

## What the artifact buys, with no goal text at all

    precedence   an action whose preconditions are unmet is out of order
    severity     an action whose effects are irreversible is the costly one

Both fall out of the catalogue. Neither needs the goal to name anything, which is
the limitation the lexical rungs could not escape.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import urllib.error
import urllib.request

from benchmarks._http import post_json

CACHE = pathlib.Path(__file__).with_name("_ontology_cache.json")
DEPLOYMENT = os.environ.get("CLAYSEAL_MONITOR_DEPLOYMENT", "gpt-4.1-mini")

SYSTEM = (
    "You write planning operators for tools, in the style of PDDL. For each "
    "tool you are given, output what facts must already hold before it can run, "
    "what facts it makes true, what facts it makes false, and whether its "
    "effects can be undone by another tool in the same catalogue. Facts are "
    "short lowercase snake_case labels naming a state of the world, and the SAME "
    "label must be reused across tools when they refer to the same state. Return "
    "only JSON: a list of objects with keys tool, preconditions, establishes, "
    "destroys, reversible."
)


def _schema_only(tools: list[dict]) -> list[dict]:
    """The compiler's entire input. Asserted, not promised."""
    out = []
    for t in tools or ():
        f = t.get("function", t)
        out.append({
            "name": f.get("name", ""),
            "description": f.get("description", ""),
            "parameters": sorted((f.get("parameters") or {})
                                 .get("properties", {}) or {}),
        })
    return out


def _ask(payload: str) -> str:
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "").rstrip("/")
    key = os.environ.get("AZURE_OPENAI_KEY") or os.environ.get(
        "AZURE_OPENAI_API_KEY", "")
    if not endpoint or not key:
        raise RuntimeError("compile needs AZURE_OPENAI_ENDPOINT and _KEY")
    url = (f"{endpoint}/openai/deployments/{DEPLOYMENT}"
           f"/chat/completions?api-version=2024-10-21")
    if not url.startswith("https://"):
        raise RuntimeError("endpoint must be https")
    body = json.dumps({
        "messages": [{"role": "system", "content": SYSTEM},
                     {"role": "user", "content": payload}],
        "temperature": 0, "max_tokens": 1400,
    }).encode()
    # The scheme is pinned to https above, which is what S310 asks for.
    with post_json(url, data=body,
                   headers={"Content-Type": "application/json", "api-key": key},
                   timeout=90) as r:
        return json.loads(r.read())["choices"][0]["message"]["content"]


def compile_catalogue(tools: list[dict], *, cache: dict) -> list[dict] | None:
    schema = _schema_only(tools)
    if not schema:
        return None
    digest = hashlib.sha256(
        (DEPLOYMENT + json.dumps(schema, sort_keys=True)).encode()).hexdigest()
    if digest in cache:
        return cache[digest]
    try:
        raw = _ask(json.dumps(schema, indent=1))
    except (urllib.error.URLError, OSError, KeyError, ValueError, RuntimeError):
        return None
    raw = raw.strip().removeprefix("```json").removeprefix("```").removesuffix("```")
    try:
        specs = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(specs, list):
        return None
    cache[digest] = specs
    return specs


def load_cache() -> dict:
    if CACHE.exists():
        return json.loads(CACHE.read_text())
    return {}


def save_cache(cache: dict) -> None:
    CACHE.write_text(json.dumps(cache, indent=1, sort_keys=True))


def main(argv=None) -> int:
    from benchmarks.bpl.registry import SCENARIOS, get_scenario
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--limit", type=int, default=0)
    args = p.parse_args(argv)

    cache = load_cache()
    names = [n for n in SCENARIOS if get_scenario(n).tools]
    if args.limit:
        names = names[: args.limit]
    ok = fail = 0
    for i, n in enumerate(names, 1):
        specs = compile_catalogue(get_scenario(n).tools, cache=cache)
        if specs is None:
            fail += 1
        else:
            ok += 1
        # Checkpoint as we go. A run killed by a timeout otherwise discards every
        # answer it paid for, which turns a cache into a liability. `llm_monitor`
        # carries the same guard for the same reason.
        if i % 10 == 0:
            save_cache(cache)
    save_cache(cache)
    print(f"compiled {ok} catalogues, {fail} failed, cache {CACHE.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
