"""Edges supplied from outside, for what static analysis cannot see.

Dynamic dispatch, dependency injection and configuration-driven wiring produce
real dependencies with no import to read. `load_reference_edges` takes those as
input so a lease can include a file the graph could not reach.

Malformed entries are skipped rather than raised on, and this file is an input to
RANKING rather than to enforcement: an edge here can bring a file into a lease's
candidate set, and `enforcement.py` still decides whether the path is allowed.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_reference_edges(path: str | Path) -> list[tuple[str, str]]:
    """
    Load optional "exact ref" edges from an external compiler index.

    DP-9 is intentionally optional; this function is the integration seam. The actual production
    edge extractor can be SCIP/LSIF/LSP-based and write a simple JSON or JSONL edge file.

    Accepted formats:
    - JSON list: [{"from": "a.py", "to": "b.py"}, ...]
    - JSONL: one object per line with {"from": "...", "to": "..."}
    """
    p = Path(path)
    if not p.is_file():
        return []

    raw = p.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        return []

    edges: list[tuple[str, str]] = []
    if raw.startswith("["):
        items = json.loads(raw)
        if not isinstance(items, list):
            raise ValueError("reference edges JSON must be a list")
        for item in items:
            _append_edge(edges, item)
    else:
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            _append_edge(edges, json.loads(line))

    # Normalize + de-dupe.
    out: set[tuple[str, str]] = set()
    for src, dst in edges:
        s = str(src).replace("\\", "/").lstrip("/")
        d = str(dst).replace("\\", "/").lstrip("/")
        if s and d and s != d:
            out.add((s, d))
    return sorted(out)


def _append_edge(out: list[tuple[str, str]], raw: Any) -> None:
    if not isinstance(raw, dict):
        return
    src = raw.get("from")
    dst = raw.get("to")
    if isinstance(src, str) and isinstance(dst, str):
        out.append((src, dst))

