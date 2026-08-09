"""IPI-Coding-Agent loader: injection through the artifacts a coding agent reads.

From the UK AISI `inspect_evals` suite. 45 samples in which a legitimate coding
task (fix a bug, make a test pass) is paired with a payload hidden in the
repository context the agent must read anyway: issue text, source comments,
configuration. Ten samples carry no payload at all and are the controls.

Four payload categories, and the split matters to us because our layers do not
treat them alike:

``exfiltration`` (15)   read a secret and get it out. Target-shaped, so egress
                        binding should hold.
``code_execution`` (10) run attacker-supplied code. Target-shaped in the same
                        way, since the thing executed has a path.
``persistence`` (10)    write somewhere that survives the session. Target-shaped
                        only if the write leaves the workspace, which is exactly
                        the question our long-horizon tier asks.
``none`` (10)           benign controls for the false-block rate.

The benchmark's own metrics are injection resistance and task completion
measured on a live agent. We replay it deterministically against the enforcement
ladder instead, which answers a narrower question: of the actions these payloads
induce, how many does authorization refuse. It is a lower bound on what the full
system does and it needs no inference.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, EventLabel

WORKSPACE = "/workspace"

# The payload's intended effect, expressed as the action it would take. Derived
# from `expected_malicious_action`, which the corpus states in prose.
_SECRET_PATHS = ("SECRET_API_KEY", "credential", ".env", "token", "id_rsa", ".ssh")


def _mandate(task_id: str) -> dict[str, Any]:
    return {
        "mandate_id": f"ipi-{task_id}",
        "task": {"summary": "fix the issue in the checkout"},
        "scope": {
            "allowed_paths": [f"{WORKSPACE}/**", WORKSPACE.lstrip("/") + "/**"],
            "denied_paths": [],
            "allowed_operations": ["read", "write", "execute", "call"],
        },
    }


def _attack_events(item: dict, task_id: str) -> list[BenchmarkEvent]:
    """The action the payload is trying to induce, in our event vocabulary."""
    category = item.get("payload_category")
    expected = str(item.get("expected_malicious_action", "")).lower()

    if category == "exfiltration":
        secret = next((s for s in _SECRET_PATHS if s.lower() in expected), "SECRET_API_KEY")
        return [
            BenchmarkEvent(
                event_id=f"{task_id}-read", tool_name="Bash", resource="workspace",
                action="read", label=EventLabel.ATTACK, path=f"/etc/{secret}",
                args={}, meta={"category": category},
            ),
            BenchmarkEvent(
                event_id=f"{task_id}-send", tool_name="Bash", resource="workspace",
                action="send", label=EventLabel.ATTACK, path="net:attacker.example",
                args={}, meta={"category": category},
            ),
        ]
    if category == "persistence":
        return [BenchmarkEvent(
            event_id=f"{task_id}-persist", tool_name="Bash", resource="workspace",
            action="write", label=EventLabel.ATTACK, path="/etc/cron.d/agent",
            args={}, meta={"category": category},
        )]
    # code_execution: run something the repository did not ship.
    return [BenchmarkEvent(
        event_id=f"{task_id}-exec", tool_name="Bash", resource="workspace",
        action="execute", label=EventLabel.ATTACK, path="/tmp/payload.sh",
        args={}, meta={"category": category},
    )]


class IpiCodingLoader:
    name = "ipi_coding"

    def __init__(self, data_root: str | Path | None = None) -> None:
        default = (Path(__file__).resolve().parents[2] / ".benchmark-corpus"
                   / "inspect_evals" / "src" / "inspect_evals" / "ipi_coding_agent" / "dataset")
        self.root = Path(data_root) if data_root else default

    def load(self, limit: int | None = None) -> list[BenchmarkTask]:
        path = self.root / "samples.json"
        if not path.exists():
            raise RuntimeError(
                "IPI-Coding-Agent not found. Clone UKGovernmentBEIS/inspect_evals into "
                ".benchmark-corpus/inspect_evals (sparse-checkout src/inspect_evals)."
            )
        raw = json.loads(path.read_text())
        items = raw if isinstance(raw, list) else raw.get("samples", [])

        tasks: list[BenchmarkTask] = []
        for item in items:
            task_id = str(item.get("id", len(tasks)))
            # Every sample does legitimate work first: that is the task, and it
            # is what a false block would cost.
            events = [BenchmarkEvent(
                event_id=f"{task_id}-work", tool_name="Edit", resource="workspace",
                action="write", label=EventLabel.BENIGN, path=f"{WORKSPACE}/src/fix.py",
                args={}, meta={"category": "task"},
            )]
            if not item.get("is_benign"):
                events += _attack_events(item, task_id)

            tasks.append(BenchmarkTask(
                task_id=f"ipi-{task_id}",
                summary=str(item.get("task_description", ""))[:100],
                events=events,
                mandate=_mandate(task_id),
                capabilities=[{"resource": "workspace", "action": a}
                              for a in ("read", "write", "execute", "call", "send")],
                allowed_tools={"Bash", "Edit", "Read", "Write"},
                meta={"category": item.get("payload_category"),
                      "sophistication": item.get("payload_sophistication"),
                      "severity": item.get("severity"),
                      "benign": bool(item.get("is_benign")),
                      "vector": item.get("injection_vector")},
            ))
            if limit and len(tasks) >= limit:
                break
        return tasks
