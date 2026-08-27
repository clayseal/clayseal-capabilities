"""ATIF MCP agent-trajectory loader, real long benign trajectories.

The ATIF-v1.2 corpus (in agentauth-receipts/benchmarks/corpus) is a set of real
MCP agent sessions: a user request followed by many agent steps, each carrying
``tool_calls`` (function_name + arguments). These are the longest real benign
trajectories available in the codebase (median 6, up to 32 tool calls per
session), which is exactly what the behavioral detector needs to calibrate a
plausible-path corridor and peer group on real data rather than synthetic.

Sessions are benign, so they serve two roles: real benign trajectories for
detector training/calibration, and a realistic base for adversarial synthesis
(the leaderboard and in-scope attack injectors operate on their benign events).
"""
from __future__ import annotations

import json
from pathlib import Path

from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, EventLabel

_WRITE = ("create", "update", "delete", "send", "pay", "transfer", "set", "add",
          "remove", "cancel", "book", "post", "share", "write", "schedule", "execute")
_READ = ("get", "list", "search", "read", "find", "view", "show", "check",
         "fetch", "lookup", "query", "describe")


def _verb(tool: str) -> str:
    low = tool.lower()
    for v in _WRITE:
        if low.startswith(v) or f"_{v}" in low:
            return "transfer" if v in ("pay", "transfer") else ("send" if v == "send" else "write")
    for v in _READ:
        if low.startswith(v) or f"_{v}" in low:
            return "read"
    return "call"


def _first_user_message(steps: list[dict]) -> str:
    for s in steps:
        if s.get("source") == "user" and s.get("message"):
            return str(s["message"])
    return "mcp session"


def _session_to_task(path: Path, index: int) -> BenchmarkTask | None:
    data = json.loads(path.read_text())
    steps = data.get("steps", [])
    events: list[BenchmarkEvent] = []
    step_no = 0
    for s in steps:
        for call in s.get("tool_calls", []) or []:
            tool = str(call.get("function_name") or call.get("name") or "")
            if not tool:
                continue
            args = call.get("arguments") if isinstance(call.get("arguments"), dict) else {}
            events.append(BenchmarkEvent(
                event_id=f"atif-{index}-{step_no}", tool_name=tool,
                resource=f"mcp:tool:{tool}", action=_verb(tool), args=dict(args),
                label=EventLabel.BENIGN, meta={"source": "atif"},
            ))
            step_no += 1
    if not events:
        return None

    tools = sorted({e.tool_name for e in events})
    authorized: dict[str, list[dict]] = {}
    for e in events:
        if e.args:
            authorized.setdefault(e.tool_name, []).append(dict(e.args))
    return BenchmarkTask(
        task_id=str(data.get("session_id") or f"atif-{index}"),
        summary=_first_user_message(steps),
        events=events,
        allowed_tools=set(tools),
        capabilities=sorted(
            ({"resource": e.resource, "action": e.action} for e in events),
            key=lambda c: (c["resource"], c["action"]),
        ),
        authorized_args=authorized,
        mandate={
            "grant_id": f"atif-grant-{index}",
            "issuer": "did:clayseal:atif",
            "issued_at": "2026-03-18T00:00:00+00:00",
            "expires_at": "2026-03-19T00:00:00+00:00",
            "allowed_actions": sorted({e.action for e in events}),
            "allowed_resources": [f"mcp:tool:{t}" for t in tools],
        },
        # Per-app goal bucket: each ATIF app is its own tool surface. With one
        # session per app the structural corridor abstains (min_samples) rather
        # than over-flag a single heterogeneous bucket, the honest degradation
        # when per-goal data is too thin. tau2 (hundreds/domain) is the
        # well-sampled counterpart.
        meta={"source": "atif", "app": path.parent.name, "goal_kind": f"atif:{path.parent.name}"},
    )


def _dedup_caps(caps: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out: list[dict] = []
    for c in caps:
        key = (c["resource"], c["action"])
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


class AtifLoader:
    name = "atif"

    def __init__(self, data_root: str | None = None) -> None:
        # Default to the sibling receipts corpus if present.
        default = Path(__file__).resolve().parents[3] / "agentauth-receipts" / \
            "benchmarks" / "corpus" / "mcp_agent_trajectory_benchmark"
        self._root = Path(data_root) if data_root else default

    def load(self, *, limit: int | None = None) -> list[BenchmarkTask]:
        if not self._root.exists():
            raise RuntimeError(
                f"ATIF corpus not found at {self._root}. Pass data_root pointing at "
                "agentauth-receipts/benchmarks/corpus/mcp_agent_trajectory_benchmark."
            )
        tasks: list[BenchmarkTask] = []
        for i, path in enumerate(sorted(self._root.glob("*/trajectory.json"))):
            task = _session_to_task(path, i)
            if task is not None:
                task.capabilities = _dedup_caps(task.capabilities)
                tasks.append(task)
            if limit and len(tasks) >= limit:
                break
        return tasks
