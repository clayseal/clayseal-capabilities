"""BFCL multi-turn *file-system* ground-truth trajectories.

Gorilla BFCL's multi-turn split ships, in ``possible_answer/``, the ground-truth
call sequence for each task as call strings like ``mv(source='a', destination='b')``.
The ``gorilla_file_system`` tool surface (cd/ls/cat/mkdir/mv/cp/rm/grep/diff/...)
is the same surface a coding agent uses, which makes these trajectories the
natural **benign** counterpart to RedCode's risky operations: real recorded work,
not synthesized traffic.

This module deliberately exposes only the parsed calls; the caller decides how to
label and scope them. ``benchmarks/datasets/bfcl.py`` remains the standalone BFCL
loader — this is the narrower file-system-only view RedCode pairs against.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

_CALL_RE = re.compile(r"^\s*([A-Za-z_][\w.]*)\s*\((.*)\)\s*$", re.DOTALL)

# The gorilla_file_system tool surface; other multi-turn tasks use trading /
# travel / vehicle APIs that a coding-agent mandate says nothing about.
FS_TOOLS = {
    "cd", "ls", "cat", "mkdir", "mv", "cp", "rm", "rmdir", "touch", "echo",
    "grep", "diff", "sort", "wc", "du", "pwd", "tail", "head", "find",
}


def _default_root() -> Path:
    return Path(__file__).resolve().parents[2] / ".benchmark-corpus" / "bfcl"


def _parse_call(text: str) -> tuple[str, dict[str, Any]] | None:
    m = _CALL_RE.match(text)
    if not m:
        return None
    name, arg_str = m.group(1), m.group(2).strip()
    args: dict[str, Any] = {}
    if arg_str:
        try:
            call = ast.parse(f"_f({arg_str})", mode="eval").body
        except SyntaxError:
            return (name, args)
        for kw in getattr(call, "keywords", []):
            try:
                args[kw.arg] = ast.literal_eval(kw.value)
            except Exception:  # noqa: BLE001 - non-literal arg; keep the name
                args[kw.arg] = "<expr>"
        # Positional args appear in a few entries, e.g. sort('report.pdf').
        for i, pos in enumerate(getattr(call, "args", [])):
            try:
                args[f"arg{i}"] = ast.literal_eval(pos)
            except Exception:  # noqa: BLE001
                args[f"arg{i}"] = "<expr>"
    return (name, args)


def load_filesystem_trajectories(
    data_root: str | None = None,
    *,
    limit: int | None = None,
) -> list[tuple[str, list[tuple[str, dict[str, Any]]]]]:
    """Return ``[(task_id, [(tool, args), ...]), ...]`` for file-system tasks.

    A trajectory is kept only when *every* call is on the file-system surface,
    so the benign corpus stays on the tool surface the coding mandate covers.
    """
    root = Path(data_root) if data_root else _default_root()
    answers = root / "data" / "possible_answer"
    if not answers.exists():
        raise RuntimeError(
            f"BFCL multi-turn ground truth not found at {answers}. Fetch it with:\n"
            "  B=https://raw.githubusercontent.com/ShishirPatil/gorilla/main/"
            "berkeley-function-call-leaderboard/bfcl_eval/data\n"
            "  curl -sL $B/possible_answer/BFCL_v4_multi_turn_base.json -o "
            f"{answers}/BFCL_v4_multi_turn_base.json"
        )
    out: list[tuple[str, list[tuple[str, dict[str, Any]]]]] = []
    for path in sorted(answers.glob("BFCL_v*_multi_turn_*.json")):
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            calls: list[tuple[str, dict[str, Any]]] = []
            fs_only = True
            for turn in row.get("ground_truth", []):
                for call_str in turn:
                    parsed = _parse_call(call_str)
                    if parsed is None:
                        continue
                    tool, args = parsed
                    if tool not in FS_TOOLS:
                        fs_only = False
                        break
                    calls.append((tool, args))
                if not fs_only:
                    break
            if fs_only and calls:
                out.append((str(row.get("id", f"bfcl-{len(out)}")), calls))
            if limit and len(out) >= limit:
                return out
    return out
