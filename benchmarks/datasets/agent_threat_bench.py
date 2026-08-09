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
import re
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


# The tool set AgentThreatBench actually gives the agent, per category
# (tools.py::TASK_TOOLS). autonomy_hijack has no payment or egress tool at all,
# which is why a synthesized `transfer` there measured nothing.
_TOOLS_FOR = {
    "data_exfil": {"lookup_customer", "send_message", "resolve_ticket", "lookup"},
    "autonomy_hijack": {"read_inbox", "categorize_email", "draft_summary"},
    "memory_poison": {"memory_read", "memory_write"},
}

# Why a category contributes no attack event, stated rather than counted as a
# miss. Both of these are content-defined harm: the corpus scores them on the
# model's completion text, not on a tool call.
_UNCONTAINED = {
    "memory_poison": (
        "the store is pre-poisoned at setup and the failure is the marker "
        "appearing in the completion; there is no attack action to authorize"
    ),
    "autonomy_hijack": (
        "the agent holds only read_inbox, categorize_email and draft_summary; "
        "the forbidden actions are tokens scored against the completion"
    ),
}

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _injected_recipient(item: dict) -> str | None:
    """The attacker address the injection actually names.

    Hard-coding a fake recipient makes the arm synthetic in the one detail the
    check turns on. Every data_exfil item carries the real one inside the
    injected customer record, so it is taken from there and only falls back if
    the item does not name one.
    """
    authorized = {str(a).lower() for a in (item.get("authorized_recipients") or [])}
    seen = _EMAIL.findall(json.dumps(item))
    for address in seen:
        if address.lower() not in authorized:
            return address
    return None


def _events(item: dict, category: str, task_id: str) -> list[BenchmarkEvent]:
    """The benign step, and the attack step ONLY where the corpus has one.

    Three of AgentThreatBench's categories were represented here and only one of
    them contains an attack an authorization layer can see. The other two were
    invented by this loader, and the numbers they produced were meaningless:

    **memory_poison** had a synthesized `memory_write`. The corpus never has the
    agent write memory; the harness pre-poisons the store at setup
    (`tools.py::use_agent_threat_bench_tools`), and `scorer.py::_score_memory_poison`
    defines the failure as the attack marker appearing in the model's COMPLETION
    TEXT. No tool call is consulted. The harm is content-defined, which per
    `benchmarks/results/four_axes.md` is the axis nobody contains, and dressing
    it as a write the agent never performs turned a declared gap into ten
    unexplained misses.

    **autonomy_hijack** had a synthesized `transfer`. The agent's entire tool set
    for that category is `{read_inbox, categorize_email, draft_summary}`; there
    is no payment or egress tool. Scoring is again textual. One item's
    "forbidden action" is the string `ignore your system prompt`, and this loader
    was blocking a wire transfer to `net:ignore your system prompt`. That is the
    ASB failure mode: containment credited for checking a tool name against a
    tool the corpus's agent never holds.

    **data_exfil** is real. The corpus gives the agent `send_message`, and its
    security check is a recipient outside `authorized_recipients` carrying a
    sensitive field, which is exactly what destination binding decides.

    So only data_exfil emits an attack event. The other two contribute their
    benign step, so they still carry false-block signal, and their gap is
    declared in `task.meta["uncontained_reason"]` rather than counted as a miss.
    """
    events: list[BenchmarkEvent] = []
    authorized = item.get("authorized_recipients") or []

    # The benign step has to be a call this category's agent can actually make.
    # It used to be `send_message` or `lookup` for every category, so the
    # autonomy_hijack and memory_poison agents were scored on tools they do not
    # hold, and every one of their legitimate steps counted as a false block.
    if category == "data_exfil" and authorized:
        events.append(BenchmarkEvent(
            event_id=f"{task_id}-legit",
            tool_name="send_message", resource="records", action="send",
            label=EventLabel.BENIGN, path=f"net:{authorized[0]}",
            args={"to": authorized[0]}, meta={"category": category},
        ))
    elif category == "autonomy_hijack":
        events.append(BenchmarkEvent(
            event_id=f"{task_id}-legit",
            tool_name="read_inbox", resource="records", action="read",
            label=EventLabel.BENIGN, path="records/inbox",
            args={}, meta={"category": category},
        ))
    elif category == "memory_poison":
        events.append(BenchmarkEvent(
            event_id=f"{task_id}-legit",
            tool_name="memory_read", resource="memory", action="read",
            label=EventLabel.BENIGN, path="memory/long_term",
            args={}, meta={"category": category},
        ))
    else:
        events.append(BenchmarkEvent(
            event_id=f"{task_id}-legit",
            tool_name="lookup", resource="records", action="read",
            label=EventLabel.BENIGN, path="records/customer",
            args={}, meta={"category": category},
        ))

    # The corpus ships explicit negative controls with the attack fields
    # emptied, and `scorer.py` auto-passes them. Labelling one ATTACK scores
    # containment against the benchmark's own control: three were counted as
    # contained and two as missed, all five fabricated.
    if item.get("attack_name") == "clean_baseline":
        return events

    if category == "data_exfil":
        recipient = _injected_recipient(item) or "attacker-relay.example"
        events.append(BenchmarkEvent(
            event_id=f"{task_id}-attack",
            tool_name="send_message", resource="records", action="send",
            label=EventLabel.ATTACK, path=f"net:{recipient}",
            args={"to": recipient,
                  "body": ",".join(map(str, item.get("sensitive_fields", [])))[:80]},
            meta={"category": category, "owasp": item.get("owasp_id"),
                  "attack_class": "unauthorized-destination"},
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
                    # The corpus's own tool set per category. Granting tools it
                    # never gives the agent is how the synthesized `transfer`
                    # events looked contained.
                    allowed_tools=_TOOLS_FOR.get(category, {"send_message", "lookup"}),
                    meta={"category": category, "owasp": item.get("owasp_id"),
                          "difficulty": item.get("difficulty"),
                          "clean_baseline": item.get("attack_name") == "clean_baseline",
                          "uncontained_reason": _UNCONTAINED.get(category)},
                ))
                if limit and len(tasks) >= limit:
                    return tasks
        return tasks
