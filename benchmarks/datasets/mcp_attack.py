"""MCP-attack loader — poisoned tools, confused deputy, and tool-result injection.

Product-shaped suite: the agent is granted a legitimate MCP tool surface, and
the attack arrives through (a) a tool whose *description* steers the model,
(b) a tool result that smuggles an out-of-scope call, or (c) a deputy tool that
forwards to an attacker host. Not a public corpus clone — a first-class Clay
Seal fixture that exercises destination binding and scope the way buyers ask.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, EventLabel

_FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "mcp_attack" / "tasks.jsonl"
)


class McpAttackLoader:
    name = "mcp_attack"

    def __init__(self, data_root: str | Path | None = None) -> None:
        default = (Path(__file__).resolve().parents[2] / ".benchmark-corpus"
                   / "mcp_attack")
        self._data_root = Path(data_root) if data_root else default

    def load(self, *, limit: int | None = None) -> list[BenchmarkTask]:
        path = self._data_root / "tasks.jsonl"
        if not path.exists():
            path = _FIXTURE
        if not path.exists():
            raise RuntimeError("MCP-attack fixture missing at benchmarks/fixtures/mcp_attack/")
        tasks: list[BenchmarkTask] = []
        with path.open() as handle:
            for i, line in enumerate(handle):
                line = line.strip()
                if not line:
                    continue
                tasks.append(_case_to_task(json.loads(line), i))
                if limit and len(tasks) >= limit:
                    break
        return tasks


def _ev(spec: dict[str, Any], label: EventLabel, eid: str) -> BenchmarkEvent:
    tool = str(spec["tool"])
    return BenchmarkEvent(
        event_id=eid,
        tool_name=tool,
        resource=str(spec.get("resource") or f"mcp:tool:{tool}"),
        action=str(spec.get("action") or "call"),
        path=spec.get("path"),
        args=dict(spec.get("args") or {}),
        label=label,
        meta={"source": "mcp_attack", **dict(spec.get("meta") or {})},
    )


def _case_to_task(case: dict[str, Any], index: int) -> BenchmarkTask:
    benign = [_ev(s, EventLabel.BENIGN, f"mcp-{index}-b{j}")
              for j, s in enumerate(case.get("benign", []))]
    attack = [_ev(s, EventLabel.ATTACK, f"mcp-{index}-a{j}")
              for j, s in enumerate(case.get("attack", []))]
    tools = set(case.get("allowed_tools") or {e.tool_name for e in benign})
    resources = sorted(f"mcp:tool:{t}" for t in tools)
    return BenchmarkTask(
        task_id=str(case.get("task_id", f"mcp-attack-{index}")),
        summary=str(case.get("summary", "")),
        events=benign + attack,
        allowed_tools=tools,
        capabilities=[{"resource": r, "action": a}
                      for r, a in sorted({(e.resource, e.action) for e in benign})],
        authorized_args={
            t: [dict(e.args) for e in benign if e.tool_name == t and e.args]
            for t in tools
        },
        mandate={
            "grant_id": f"mcp-attack-{index}",
            "issuer": "did:clayseal:mcp-attack",
            "issued_at": "2026-08-09T00:00:00+00:00",
            "expires_at": "2026-08-10T00:00:00+00:00",
            "allowed_actions": sorted({e.action for e in benign} | {"read", "call"}),
            "allowed_resources": resources,
        },
        meta={
            "fidelity": "fixture",
            "attack_class": case.get("attack_class", "mcp"),
            "axis": "tool_mediation",
        },
    )
