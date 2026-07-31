"""tau2-bench loader — domain-bucketed benign tool-policy trajectories.

Each tau2 task carries ``evaluation_criteria.actions``: the ground-truth
tool-call sequence a correct agent makes. Tasks are grouped by domain (airline,
retail, telecom, mock, banking_knowledge), and every task in a domain shares the
same tool surface, so a domain is a well-sampled goal bucket — exactly the
per-goal calibration data the detector's corridor and peer group need (telecom
alone has ~2,285 tasks). Real, structured, deterministic: no LLM required.
"""
from __future__ import annotations

import json
from pathlib import Path

from benchmarks.core.events import BenchmarkTask
from benchmarks.datasets._common import benign_task_from_calls


def _default_root() -> Path:
    return Path(__file__).resolve().parents[3] / "agentauth-receipts" / "benchmarks" / \
        "corpus" / "tau2_bench" / "data" / "tau2" / "domains"


class Tau2Loader:
    name = "tau2"

    def __init__(self, data_root: str | None = None, domains: list[str] | None = None) -> None:
        self._root = Path(data_root) if data_root else _default_root()
        self._domains = domains

    def load(self, *, limit: int | None = None) -> list[BenchmarkTask]:
        if not self._root.exists():
            raise RuntimeError(
                f"tau2 corpus not found at {self._root}. Point data_root at "
                "agentauth-receipts/benchmarks/corpus/tau2_bench/data/tau2/domains."
            )
        domains = self._domains or sorted(
            p.name for p in self._root.iterdir() if (p / "tasks.json").exists()
        )
        tasks: list[BenchmarkTask] = []
        for domain in domains:
            path = self._root / domain / "tasks.json"
            if not path.exists():
                continue
            for entry in json.loads(path.read_text()):
                task = _task_from_tau2(entry, domain)
                if task is not None:
                    tasks.append(task)
                if limit and len(tasks) >= limit:
                    return tasks
        return tasks


def _task_from_tau2(entry: dict, domain: str) -> BenchmarkTask | None:
    actions = (entry.get("evaluation_criteria") or {}).get("actions") or []
    calls = [
        (str(a.get("name", "")), a.get("arguments") or {})
        for a in actions if a.get("name")
    ]
    if not calls:
        return None
    return benign_task_from_calls(
        task_id=f"tau2-{domain}-{entry.get('id', '')}",
        summary=str(entry.get("description") or entry.get("id") or ""),
        calls=calls, goal_kind=f"tau2:{domain}", source="tau2",
    )
