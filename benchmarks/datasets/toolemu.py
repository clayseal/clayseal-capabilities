"""ToolEmu loader — emulated tool-agent risk cases mapped to BenchmarkTask.

ToolEmu (Ruan et al., "Identifying the Risks of LM Agents with an Emulated
Sandbox") curates cases of a user instruction over a set of toolkits, each with
enumerated *potential risky actions*. Unlike AgentDojo/InjecAgent it ships no
deterministic ground-truth tool-call sequence — risk is scored by an LLM
emulator and judge — so a faithful replay needs one small preprocessing step
that pins, per case, the legitimate calls and the risky calls as structured
tool invocations.

Two input paths, preferred first:

1. ``<data_root>/clayseal_traces.jsonl`` — one normalized trace per line::

     {"task_id","summary","allowed_tools":[...],
      "benign":[{"tool","action","args","path"}...],
      "attack":[{"tool","action","args","path"}...]}

   This is the honest, fully-scored path (containment across every ladder rung).

2. Raw ToolEmu case JSON (``*.json`` with ``Toolkits`` / ``User Instruction`` /
   ``Potential Risky Actions``) — a coarse fallback: benign events come from the
   named toolkits' read tools, attack events from each risky action's tool name.
   Argument- and path-level rungs can't be scored without structured args, so
   this path exercises only the tool/action rungs; it is clearly labeled in each
   task's ``meta["fidelity"]``.

Run on the Azure VM alongside AgentDojo; see ``benchmarks/README.md``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, EventLabel

_READ_ACTIONS = {"read", "get", "list", "search", "view"}


class ToolEmuLoader:
    name = "toolemu"

    def __init__(self, data_root: str | None = None) -> None:
        self._data_root = Path(data_root) if data_root else None

    def load(self, *, limit: int | None = None) -> list[BenchmarkTask]:
        if self._data_root is None or not self._data_root.exists():
            raise RuntimeError(
                "ToolEmu data not found. Pass its path: "
                "ToolEmuLoader(data_root='.../ToolEmu/assets'). Prefer a "
                "normalized clayseal_traces.jsonl; see benchmarks/README.md."
            )
        normalized = self._data_root / "clayseal_traces.jsonl"
        if normalized.exists():
            tasks = _load_normalized(normalized)
        else:
            tasks = _load_raw(self._data_root)
        if not tasks:
            raise RuntimeError(
                f"ToolEmu produced no tasks from {self._data_root}. Provide "
                "clayseal_traces.jsonl or raw case JSON with 'Toolkits' and "
                "'Potential Risky Actions'."
            )
        return tasks[:limit] if limit else tasks


def _action_for(tool_name: str, default: str) -> str:
    lowered = tool_name.lower()
    if any(lowered.startswith(v) or v in lowered for v in _READ_ACTIONS):
        return "read"
    return default


def _event(spec: dict[str, Any], label: EventLabel, event_id: str,
           default_action: str) -> BenchmarkEvent:
    tool = str(spec.get("tool") or spec.get("name") or "")
    args = dict(spec.get("args") or {})
    return BenchmarkEvent(
        event_id=event_id,
        tool_name=tool,
        resource=f"mcp:tool:{tool}",
        action=str(spec.get("action") or _action_for(tool, default_action)),
        path=spec.get("path"),
        args=args,
        label=label,
        meta={"source": "toolemu"},
    )


def _collect_authorized_args(benign: list[BenchmarkEvent]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for e in benign:
        if e.args:
            out.setdefault(e.tool_name, []).append(dict(e.args))
    return out


def _authorization(benign: list[BenchmarkEvent]) -> dict[str, Any]:
    allowed_tools = {e.tool_name for e in benign}
    resources = sorted({e.resource for e in benign})
    actions = sorted({e.action for e in benign})
    return {
        "allowed_tools": allowed_tools,
        "capabilities": [
            {"resource": r, "action": a}
            for r, a in sorted({(e.resource, e.action) for e in benign})
        ],
        "authorized_args": _collect_authorized_args(benign),
        "mandate": {
            "grant_id": "toolemu-grant",
            "issuer": "did:clayseal:toolemu",
            "issued_at": "2026-07-21T00:00:00+00:00",
            "expires_at": "2026-07-22T00:00:00+00:00",
            "allowed_actions": actions,
            "allowed_resources": resources,
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
                _event(s, EventLabel.BENIGN, f"toolemu-{i}-b{j}", "read")
                for j, s in enumerate(case.get("benign", []))
            ]
            attack = [
                _event(s, EventLabel.ATTACK, f"toolemu-{i}-a{j}", "write")
                for j, s in enumerate(case.get("attack", []))
            ]
            if not benign or not attack:
                continue
            auth = _authorization(benign)
            if case.get("allowed_tools"):
                auth["allowed_tools"] = set(case["allowed_tools"])
            tasks.append(BenchmarkTask(
                task_id=str(case.get("task_id", f"toolemu-{i}")),
                summary=str(case.get("summary", "")),
                events=benign + attack,
                meta={"fidelity": "normalized"},
                **auth,
            ))
    return tasks


_READ_PREFIXES = ("search", "get", "read", "list", "view", "find", "show",
                  "query", "check", "retrieve", "describe", "lookup")
_WRITE_PREFIXES = ("create", "update", "delete", "send", "share", "post",
                   "transfer", "set", "add", "remove", "cancel", "book", "pay",
                   "execute", "run", "grant", "revoke", "modify", "write")


def _tool_action(tool: str) -> str | None:
    low = tool.lower()
    if any(low.startswith(p) for p in _READ_PREFIXES):
        return "read"
    if any(low.startswith(p) for p in _WRITE_PREFIXES):
        return "write"
    return None


def _load_raw(root: Path) -> list[BenchmarkTask]:
    """Build tasks from ToolEmu assets: read on an authorized toolkit is benign;
    a destructive write in that toolkit is the underspecification risk.
    """
    cases_path = root / "all_cases.json"
    toolkits_path = root / "all_toolkits.json"
    if not cases_path.exists() or not toolkits_path.exists():
        return []
    cases = json.loads(cases_path.read_text())
    toolkits = json.loads(toolkits_path.read_text())
    tool_index: dict[str, list[str]] = {}
    for tk in toolkits:
        name = tk.get("toolkit") or tk.get("name_for_model") or ""
        tool_index[name] = [t.get("name", "") for t in tk.get("tools", []) if t.get("name")]

    tasks: list[BenchmarkTask] = []
    for i, case in enumerate(cases if isinstance(cases, list) else []):
        task = _case_from_toolkits(case, tool_index, i)
        if task is not None:
            tasks.append(task)
    return tasks


def _case_from_toolkits(case: dict[str, Any], tool_index: dict[str, list[str]],
                        index: int) -> BenchmarkTask | None:
    toolkits = case.get("Toolkits") or []
    tools: list[str] = []
    for tk in toolkits:
        tools.extend(tool_index.get(str(tk), []))
    reads = [t for t in tools if _tool_action(t) == "read"]
    writes = [t for t in tools if _tool_action(t) == "write"]
    if not reads or not writes:
        return None
    benign = [
        BenchmarkEvent(
            event_id=f"toolemu-{index}-b{j}", tool_name=t,
            resource=f"mcp:tool:{t}", action="read",
            label=EventLabel.BENIGN, meta={"source": "toolemu"},
        )
        for j, t in enumerate(reads)
    ]
    # The risky side effect: destructive tools in the authorized toolkit that the
    # user's (query-shaped) instruction never authorized.
    attack = [
        BenchmarkEvent(
            event_id=f"toolemu-{index}-a{j}", tool_name=t,
            resource=f"mcp:tool:{t}", action="write",
            label=EventLabel.ATTACK, meta={"source": "toolemu", "risky": True},
        )
        for j, t in enumerate(writes)
    ]
    return BenchmarkTask(
        task_id=f"toolemu-{index}",
        summary=str(case.get("User Instruction", "")),
        events=benign + attack,
        allowed_tools={t for t in reads},
        capabilities=[{"resource": f"mcp:tool:{t}", "action": "read"} for t in reads],
        mandate={
            "grant_id": f"toolemu-grant-{index}",
            "issuer": "did:clayseal:toolemu",
            "issued_at": "2026-07-21T00:00:00+00:00",
            "expires_at": "2026-07-22T00:00:00+00:00",
            "allowed_actions": ["read"],
            "allowed_resources": [f"mcp:tool:{t}" for t in reads],
        },
        meta={"fidelity": "toolkit-mapped", "toolkits": list(toolkits)},
    )
