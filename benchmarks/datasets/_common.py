"""Shared helpers for building benign BenchmarkTasks from ground-truth calls.

ATIF, tau2, and BFCL all reduce to the same shape: a goal plus an ordered list
of ``(tool, args)`` calls the agent legitimately made. This centralizes verb
classification, per-call argument binding, capability derivation, and the goal
bucket so each loader stays thin and the detector sees one consistent encoding.
"""
from __future__ import annotations

from typing import Any

from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, EventLabel

# Verb classification moved into the shipped package: it is library behaviour
# that every integration needs and the benchmark tree is not installable. Re-
# exported here so the loaders keep their existing import and the two cannot
# drift apart, because they are now the same function.
from clayseal.capabilities.tool_verbs import classify_verb


def benign_task_from_calls(
    *,
    task_id: str,
    summary: str,
    calls: list[tuple[str, dict[str, Any]]],
    goal_kind: str,
    source: str,
    issued_at: str = "2026-01-01T00:00:00+00:00",
    expires_at: str = "2026-12-31T00:00:00+00:00",
) -> BenchmarkTask | None:
    if not calls:
        return None
    events: list[BenchmarkEvent] = []
    authorized: dict[str, list[dict]] = {}
    for i, (tool, args) in enumerate(calls):
        args = dict(args) if isinstance(args, dict) else {}
        events.append(BenchmarkEvent(
            event_id=f"{task_id}-{i}", tool_name=tool, resource=f"mcp:tool:{tool}",
            action=classify_verb(tool), args=args, label=EventLabel.BENIGN,
            meta={"source": source},
        ))
        if args:
            authorized.setdefault(tool, []).append(args)

    tools = sorted({e.tool_name for e in events})
    caps_seen: set[tuple[str, str]] = set()
    caps: list[dict] = []
    for e in events:
        key = (e.resource, e.action)
        if key not in caps_seen:
            caps_seen.add(key)
            caps.append({"resource": e.resource, "action": e.action})
    return BenchmarkTask(
        task_id=task_id,
        summary=summary,
        events=events,
        allowed_tools=set(tools),
        capabilities=caps,
        authorized_args=authorized,
        mandate={
            "grant_id": f"{source}-{task_id}",
            "issuer": f"did:clayseal:{source}",
            "issued_at": issued_at,
            "expires_at": expires_at,
            "allowed_actions": sorted({e.action for e in events}),
            "allowed_resources": [f"mcp:tool:{t}" for t in tools],
        },
        # goal_kind drives the detector's per-goal bucket (calibration granularity).
        meta={"source": source, "goal_kind": goal_kind},
    )
