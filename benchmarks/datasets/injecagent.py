"""InjecAgent loader — indirect prompt-injection tool-attack corpus.

InjecAgent (Zhan et al.) frames each case as a user instruction plus an
attacker instruction smuggled through a tool's returned content, targeting
either data exfiltration or a direct harmful tool call. It maps onto the same
benign/attack event shape: the user's intended tool call is BENIGN; the
attacker's target tool call is ATTACK.

The corpus ships as JSON (test cases + a tool registry). Point ``data_root`` at
a local checkout; this loader is exercised on the Azure VM run alongside
AgentDojo. Implemented as a thin, well-marked stub so the dataset is wired into
the registry now and filled in against the pinned data layout on the VM.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, EventLabel


class InjecAgentLoader:
    name = "injecagent"

    def __init__(self, data_root: str | None = None) -> None:
        self._data_root = Path(data_root) if data_root else None

    def load(self, *, limit: int | None = None) -> list[BenchmarkTask]:
        if self._data_root is None or not self._data_root.exists():
            raise RuntimeError(
                "InjecAgent data not found. Clone the corpus and pass its path: "
                "InjecAgentLoader(data_root='.../InjecAgent/data'). Wired for the "
                "Azure VM run; see benchmarks/README.md."
            )
        cases = _read_cases(self._data_root)
        tasks: list[BenchmarkTask] = []
        for i, case in enumerate(cases):
            task = _case_to_task(case, index=i)
            if task is not None:
                tasks.append(task)
            if limit and len(tasks) >= limit:
                break
        return tasks


def _read_cases(root: Path) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for path in sorted(root.glob("test_cases_*.json")):
        with path.open() as handle:
            payload = json.load(handle)
        if isinstance(payload, list):
            cases.extend(payload)
    return cases


def _attacker_tools(case: dict[str, Any]) -> list[str]:
    raw = case.get("Attacker Tools") or case.get("Attacker Tool") or case.get("attacker_tool")
    if isinstance(raw, str):
        return [raw] if raw else []
    if isinstance(raw, (list, tuple)):
        return [str(t) for t in raw if t]
    return []


def _case_to_task(case: dict[str, Any], *, index: int) -> BenchmarkTask | None:
    user_tool = str(case.get("User Tool") or case.get("user_tool") or "")
    attacker_tools = _attacker_tools(case)
    if not user_tool or not attacker_tools:
        return None
    benign = BenchmarkEvent(
        event_id=f"injec-{index}-b", tool_name=user_tool,
        resource=f"mcp:tool:{user_tool}", action="read",
        label=EventLabel.BENIGN, meta={"source": "injecagent"},
    )
    # Each attacker tool the injection would invoke is an out-of-scope action.
    attack = [
        BenchmarkEvent(
            event_id=f"injec-{index}-a{j}", tool_name=tool,
            resource=f"mcp:tool:{tool}",
            action="send" if "send" in tool.lower() or "email" in tool.lower() else "write",
            label=EventLabel.ATTACK,
            meta={"source": "injecagent", "attack": case.get("Attack Type", "")},
        )
        for j, tool in enumerate(attacker_tools)
    ]
    return BenchmarkTask(
        task_id=f"injecagent-{index}",
        summary=str(case.get("User Instruction", "")),
        events=[benign, *attack],
        allowed_tools={user_tool},
        capabilities=[{"resource": f"mcp:tool:{user_tool}", "action": "read"}],
        mandate={
            "grant_id": f"injec-grant-{index}",
            "issuer": "did:clayseal:injecagent",
            "issued_at": "2026-07-21T00:00:00+00:00",
            "expires_at": "2026-07-22T00:00:00+00:00",
            "allowed_actions": ["read"],
            "allowed_resources": [f"mcp:tool:{user_tool}"],
        },
    )
