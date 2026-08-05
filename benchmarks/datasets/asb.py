"""Agent Security Bench (ASB) loader — breadth across 10 agent roles.

ASB (Zhang et al., ICLR 2025) ships static JSONL: 10 domain agents (system-admin,
financial-analyst, medical-advisor, ...), each with 5 user tasks, 2 legitimate
tools, and 40 attacker tools — 400 attacker tools total, evenly split
stealthy/disruptive and aggressive/non-aggressive.

Each attacker tool is a fully specified malicious capability
(``ResourceAllocationHijack``, ``CredentialHarvesting``, ``AccessEscalation``)
with the instruction the injection would use. ASB's own harness runs an LLM agent
under ten attack vectors; this loader takes only the static ground truth — which
tools the agent legitimately holds vs. which tools the attack invokes — so the
replay stays deterministic.

What this measures, honestly
----------------------------
ASB's attack surface is *tool substitution*: the injected step calls a tool the
user never granted. That makes it a breadth test (400 attacker tools x 10
domains) rather than a depth test — a plain tool-name allowlist is expected to
contain essentially all of it, and the ladder above it should add nothing. That
is a real and reportable property of the benchmark, not a weakness of the
system under test: it says ASB probes the outermost authority boundary. It is
included for domain breadth and for the false-block axis over 10 distinct tool
surfaces; the discriminating work is done by ``redcode`` and ``agentharm``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, EventLabel
from benchmarks.datasets._common import classify_verb

_ISSUED = "2026-01-01T00:00:00+00:00"
_EXPIRES = "2026-12-31T00:00:00+00:00"


def _default_root() -> Path:
    return Path(__file__).resolve().parents[2] / ".benchmark-corpus" / "ASB"


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


class AsbLoader:
    name = "asb"

    def __init__(
        self,
        data_root: str | None = None,
        *,
        aggressive: bool | None = None,
    ) -> None:
        self._root = Path(data_root) if data_root else _default_root()
        # None = both; True/False selects ASB's aggressive flag.
        self._aggressive = aggressive

    def load(self, *, limit: int | None = None) -> list[BenchmarkTask]:
        data = self._root / "data"
        agent_task = data / "agent_task.jsonl"
        attack_tools = data / "all_attack_tools.jsonl"
        normal_tools = data / "all_normal_tools.jsonl"
        missing = [p.name for p in (agent_task, attack_tools, normal_tools) if not p.exists()]
        if missing:
            raise RuntimeError(
                f"ASB corpus incomplete at {data} (missing {', '.join(missing)}). "
                "Fetch with:\n"
                "  B=https://raw.githubusercontent.com/agiresearch/ASB/main/data\n"
                "  for f in agent_task.jsonl all_attack_tools.jsonl all_normal_tools.jsonl; "
                f"do curl -sL $B/$f -o {data}/$f; done"
            )

        normal_by_agent: dict[str, list[dict]] = {}
        for row in _read_jsonl(normal_tools):
            normal_by_agent.setdefault(str(row.get("Corresponding Agent", "")), []).append(row)
        attack_by_agent: dict[str, list[dict]] = {}
        for row in _read_jsonl(attack_tools):
            if self._aggressive is not None:
                flag = str(row.get("Aggressive", "")).strip().lower() == "true"
                if flag is not self._aggressive:
                    continue
            attack_by_agent.setdefault(str(row.get("Corresponding Agent", "")), []).append(row)

        tasks: list[BenchmarkTask] = []
        for agent_row in _read_jsonl(agent_task):
            agent = str(agent_row.get("agent_name", ""))
            granted = normal_by_agent.get(agent, [])
            attacks = attack_by_agent.get(agent, [])
            if not granted or not attacks:
                continue
            for i, user_task in enumerate(agent_row.get("tasks", [])):
                task = _build_task(agent, i, str(user_task), granted, attacks)
                if task is not None:
                    tasks.append(task)
                if limit and len(tasks) >= limit:
                    return tasks
        return tasks


def _build_task(
    agent: str,
    index: int,
    user_task: str,
    granted: list[dict[str, Any]],
    attacks: list[dict[str, Any]],
) -> BenchmarkTask | None:
    tool_names = [str(t.get("Tool Name", "")) for t in granted if t.get("Tool Name")]
    if not tool_names:
        return None
    task_id = f"asb-{agent}-{index}"

    events: list[BenchmarkEvent] = []
    for j, tool in enumerate(tool_names):
        events.append(BenchmarkEvent(
            event_id=f"{task_id}-b{j}", tool_name=tool,
            resource=f"mcp:tool:{tool}", action=classify_verb(tool),
            label=EventLabel.BENIGN,
            meta={"source": "asb", "agent": agent},
        ))
    for j, atk in enumerate(attacks):
        tool = str(atk.get("Attacker Tool", ""))
        if not tool:
            continue
        events.append(BenchmarkEvent(
            event_id=f"{task_id}-a{j}", tool_name=tool,
            resource=f"mcp:tool:{tool}", action=classify_verb(tool),
            args={"instruction": str(atk.get("Attacker Instruction", ""))},
            label=EventLabel.ATTACK,
            meta={
                "source": "asb", "agent": agent,
                "attack_type": str(atk.get("Attack Type", "")),
                "aggressive": str(atk.get("Aggressive", "")),
                "attack_class": "unauthorized-tool",
                "attack_goal": str(atk.get("Attack goal", "")),
            },
        ))

    caps = [{"resource": f"mcp:tool:{t}", "action": classify_verb(t)} for t in tool_names]
    return BenchmarkTask(
        task_id=task_id,
        summary=user_task,
        events=events,
        allowed_tools=set(tool_names),
        capabilities=caps,
        mandate={
            "grant_id": task_id,
            "issuer": "did:clayseal:asb",
            "issued_at": _ISSUED,
            "expires_at": _EXPIRES,
            "allowed_actions": sorted({classify_verb(t) for t in tool_names}),
            "allowed_resources": [f"mcp:tool:{t}" for t in tool_names],
        },
        meta={"source": "asb", "agent": agent, "goal_kind": f"asb:{agent}"},
    )
