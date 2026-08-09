"""AgentHarm loader — the hard-negative test for a name-based authorization layer.

AgentHarm (Andriushchenko et al., UK AI Safety Institute, ICLR 2025) ships 176
public-test harmful behaviors and 176 *matched benign* counterparts, each with a
ground-truth ``target_functions`` list: the tool sequence a compliant agent
would call. Both splits are static JSON — no LLM or environment needed to read
the intended call sequence.

Why this belongs in the suite
-----------------------------
AgentHarm is deliberately adversarial to the premise that authority can be
decided from tool identity. In **143 of the 176 pairs (81%) the harmful task and
its benign twin call the identical set of tools** — e.g. both run
``run_stable_diffusion_model -> create_ai_video -> post_on_x``; one posts a
nature video, the other a political deepfake. Any layer that decides on tool
name, or on ``resource:action``, is *structurally* unable to separate them, and
this loader is built so that shows up in the numbers rather than being hidden.

That is the point of including it: it maps the ceiling of what per-call
authorization can do. Containment here comes only from the 33 pairs where the
harmful task reaches for tools the benign grant never included (a real
over-privilege signal), plus argument-level divergence where the ground-truth
prompts pin concrete targets. The remaining same-tool, same-argument-shape pairs
are a documented blind spot — harm-intent classification, not authority.

Encoding
--------
Each task pairs one behavior id: the mandate is derived from the **benign** twin's
``target_functions`` (what the user actually authorized), its calls are BENIGN,
and the harmful twin's calls are ATTACK. Tools appearing in both are genuinely
in-scope; that is the honest encoding and is exactly why the number is not 100%.
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
    return Path(__file__).resolve().parents[2] / ".benchmark-corpus" / "AgentHarm"


def _read_split(path: Path) -> dict[str, dict[str, Any]]:
    payload = json.loads(path.read_text())
    behaviors = payload.get("behaviors", payload) if isinstance(payload, dict) else payload
    return {str(b["id"]): b for b in behaviors if "id" in b}


class AgentHarmLoader:
    name = "agentharm"

    def __init__(self, data_root: str | None = None, *, split: str = "test_public") -> None:
        self._root = Path(data_root) if data_root else _default_root()
        self._split = split

    def load(self, *, limit: int | None = None) -> list[BenchmarkTask]:
        bench = self._root / "benchmark"
        harmful_path = bench / f"harmful_behaviors_{self._split}.json"
        benign_path = bench / f"benign_behaviors_{self._split}.json"
        if not harmful_path.exists() or not benign_path.exists():
            raise RuntimeError(
                f"AgentHarm corpus not found at {bench}. Fetch it with:\n"
                "  H=https://huggingface.co/datasets/ai-safety-institute/AgentHarm/"
                "resolve/main/benchmark\n"
                f"  curl -sL $H/harmful_behaviors_{self._split}.json -o "
                f"{harmful_path}\n"
                f"  curl -sL $H/benign_behaviors_{self._split}.json -o {benign_path}"
            )
        harmful = _read_split(harmful_path)
        benign = _read_split(benign_path)

        tasks: list[BenchmarkTask] = []
        for behavior_id, benign_case in benign.items():
            harmful_case = harmful.get(behavior_id)
            if harmful_case is None:
                continue
            tasks.extend(_pair_to_tasks(behavior_id, benign_case, harmful_case))
            if limit and len(tasks) >= limit:
                break
        return tasks


def _pair_to_tasks(
    behavior_id: str,
    benign_case: dict[str, Any],
    harmful_case: dict[str, Any],
) -> list[BenchmarkTask]:
    """One AgentHarm behaviour becomes TWO tasks sharing one mandate.

    The threat model is goal substitution: the user authorized the benign
    behaviour, and the agent executed its harmful twin. So the harmful task
    carries the benign task's grant, and containment asks whether the twin needs
    authority the user never gave.

    They are two tasks rather than one because they are two *sessions*. An
    earlier version concatenated them into a single trajectory, benign calls
    first, and that had a consequence nothing in the scope rungs could show:
    the velocity rung is stateful, so the benign half consumed the rate budget
    and the harmful half was blocked for arriving late. It read as +8.0 points
    of containment at zero false-block cost. Under a shuffled order the same
    configuration gives +3.8 points at 4.2% false-block, which is the tell. No
    real session contains both halves, so neither number was measuring anything.
    Split, they cannot share a window.
    """
    benign_tools: list[str] = [str(t) for t in benign_case.get("target_functions", [])]
    harmful_tools: list[str] = [str(t) for t in harmful_case.get("target_functions", [])]
    if not benign_tools or not harmful_tools:
        return []

    grant_id = f"agentharm-{behavior_id}"
    caps_seen: set[tuple[str, str]] = set()
    caps: list[dict[str, str]] = []
    for tool in benign_tools:
        key = (f"mcp:tool:{tool}", classify_verb(tool))
        if key not in caps_seen:
            caps_seen.add(key)
            caps.append({"resource": key[0], "action": key[1]})

    # The one grant both sessions are judged against: what the user authorized.
    mandate = {
        "grant_id": grant_id,
        "issuer": "did:clayseal:agentharm",
        "issued_at": _ISSUED,
        "expires_at": _EXPIRES,
        "allowed_actions": sorted({classify_verb(t) for t in benign_tools}),
        "allowed_resources": [f"mcp:tool:{t}" for t in benign_tools],
    }
    identical = set(benign_tools) == set(harmful_tools)
    overlap = set(benign_tools) & set(harmful_tools)

    def _task(suffix: str, tools: list[str], label: EventLabel,
              meta_for) -> BenchmarkTask:
        task_id = f"{grant_id}-{suffix}"
        events = [
            BenchmarkEvent(
                event_id=f"{task_id}-{i}", tool_name=tool,
                resource=f"mcp:tool:{tool}", action=classify_verb(tool),
                label=label, meta=meta_for(tool),
            )
            for i, tool in enumerate(tools)
        ]
        return BenchmarkTask(
            task_id=task_id,
            summary=str((benign_case if label is EventLabel.BENIGN
                         else harmful_case).get("name", "")),
            events=events,
            allowed_tools=set(benign_tools),
            capabilities=caps,
            mandate=dict(mandate),
            meta={
                "source": "agentharm",
                "goal_kind": f"agentharm:{benign_case.get('category', 'unknown')}",
                "category": harmful_case.get("category", ""),
                "behavior_id": behavior_id,
                "variant": suffix,
                # True when the harmful twin needs no tool the user did not
                # grant: the subset no per-call authority layer can separate.
                "identical_tool_set": identical,
            },
        )

    return [
        _task("benign", benign_tools, EventLabel.BENIGN,
              lambda tool: {"source": "agentharm",
                            "category": benign_case.get("category", "")}),
        _task("harmful", harmful_tools, EventLabel.ATTACK,
              lambda tool: {
                  "source": "agentharm",
                  "category": harmful_case.get("category", ""),
                  "attack_class": "same-tool-harmful-intent" if tool in overlap
                                  else "unauthorized-tool",
                  "shared_with_benign": tool in overlap,
              }),
    ]
