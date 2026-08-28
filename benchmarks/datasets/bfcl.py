"""Gorilla BFCL loader, real function-call ground truth.

BFCL pairs a question with a provided function schema and, in
``possible_answer/``, the ground-truth call(s). Two forms are handled:

- dict form (simple / live / multiple / parallel): ``ground_truth`` is a list of
  ``{func_name: {arg: [values]}}``, short trajectories;
- multi-turn form: ``ground_truth`` is a list of turns, each a list of call
  strings like ``mv(source='a', destination='b')``, real multi-step trajectories
  over a shared tool surface (file-system ops), a well-sampled goal bucket for
  the detector.

Bucketed by category (``bfcl:<category>``) so same-surface tasks calibrate
together. Deterministic; no LLM.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from benchmarks.core.events import BenchmarkTask
from benchmarks.datasets._common import benign_task_from_calls

_CALL_RE = re.compile(r"^\s*([A-Za-z_][\w.]*)\s*\((.*)\)\s*$", re.DOTALL)


def _default_root() -> Path:
    return Path(__file__).resolve().parents[3] / "agentauth-receipts" / "benchmarks" / \
        "corpus" / "gorilla" / "berkeley-function-call-leaderboard" / "bfcl_eval" / "data"


def _parse_call_string(text: str) -> tuple[str, dict] | None:
    """Parse ``func(arg='v', n=3)`` into ``(func, {arg: v, ...})`` safely."""
    m = _CALL_RE.match(text)
    if not m:
        return None
    name, arg_str = m.group(1), m.group(2).strip()
    args: dict = {}
    if arg_str:
        try:
            call = ast.parse(f"_f({arg_str})", mode="eval").body
            for kw in getattr(call, "keywords", []):
                try:
                    args[kw.arg] = ast.literal_eval(kw.value)
                except Exception:
                    args[kw.arg] = "<expr>"
        except SyntaxError:
            return (name, {})
    return (name, args)


def _calls_from_ground_truth(gt) -> list[tuple[str, dict]]:
    calls: list[tuple[str, dict]] = []
    for item in gt or []:
        if isinstance(item, dict):
            for func, raw_args in item.items():
                args = {k: (v[0] if isinstance(v, list) and v else v)
                        for k, v in (raw_args or {}).items()}
                calls.append((func, args))
        elif isinstance(item, list):  # a multi-turn turn: list of call strings
            for s in item:
                parsed = _parse_call_string(str(s))
                if parsed:
                    calls.append(parsed)
        elif isinstance(item, str):
            parsed = _parse_call_string(item)
            if parsed:
                calls.append(parsed)
    return calls


class BfclLoader:
    name = "bfcl"

    # Categories with structured ground-truth calls worth replaying.
    _CATEGORIES = ("live_simple", "live_multiple", "live_parallel",
                   "multiple", "parallel", "multi_turn_base")

    def __init__(self, data_root: str | None = None, categories: list[str] | None = None) -> None:
        self._root = Path(data_root) if data_root else _default_root()
        self._categories = categories or list(self._CATEGORIES)

    def load(self, *, limit: int | None = None) -> list[BenchmarkTask]:
        answers = self._root / "possible_answer"
        if not answers.exists():
            raise RuntimeError(
                f"BFCL answers not found at {answers}. Point data_root at "
                "agentauth-receipts/benchmarks/corpus/gorilla/.../bfcl_eval/data."
            )
        tasks: list[BenchmarkTask] = []
        for cat in self._categories:
            path = answers / f"BFCL_v4_{cat}.json"
            if not path.exists():
                continue
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                calls = _calls_from_ground_truth(entry.get("ground_truth"))
                task = benign_task_from_calls(
                    task_id=f"bfcl-{entry.get('id', '')}",
                    summary=str(entry.get("id", "")),
                    calls=calls, goal_kind=f"bfcl:{cat}", source="bfcl",
                )
                if task is not None:
                    tasks.append(task)
                if limit and len(tasks) >= limit:
                    return tasks
        return tasks
