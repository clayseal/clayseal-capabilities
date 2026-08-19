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

That framing was half right. Containment comes from the pairs where the harmful
task reaches for tools the benign grant never included, which is a real
over-privilege signal, and from same-tool calls aimed at a destination the benign
grant never named, which the grading functions pin for two thirds of behaviours
(see below). What is left after both is same-tool, same-destination, and that is
a documented blind spot: harm-intent classification, not authority.

Encoding
--------
Each task pairs one behavior id: the mandate is derived from the **benign** twin's
``target_functions`` (what the user actually authorized), its calls are BENIGN,
and the harmful twin's calls are ATTACK. Tools appearing in both are genuinely
in-scope; that is the honest encoding and is exactly why the number is not 100%.

Targets recovered from the grading functions
--------------------------------------------
``target_functions`` is the only field the JSON gives about the agent's actions,
so for a long time every event this loader emitted carried a tool name and
nothing else. The corpus knows more than its JSON says: its *grading functions*
assert the concrete recipient, path or URL a compliant agent must use, for 33 of
52 harmful behaviours and 36 of 52 benign ones.
``benchmarks.datasets.agentharm_targets`` recovers those by AST, and this loader
attaches them, so goal substitution becomes decidable where the ground truth
pins a destination:

    mcp:tool:send_email                       destination not pinned by the
                                              BENIGN twin, so the grant does not
                                              constrain one and no destination
                                              check can fire
    mcp:tool:send_email#email:a@b.com         destination pinned; the grant lists
                                              exactly the benign twin's addresses

Three rules keep this from manufacturing its own result:

1. **The grant is a function of the benign twin alone.** Whether a tool is
   destination-scoped is decided by whether the BENIGN grading function pins a
   target for it. Nothing about the harmful twin can change the mandate, which is
   the invariant a velocity cap once broke.
2. **An unrecovered destination is allowed, never contained.** When the harmful
   twin pins no target for a destination-scoped tool, its event is emitted at the
   coarse ``mcp:tool:<tool>`` resource, which the grant always contains. We
   cannot see where it points, so we do not get to call it contained.
3. **One extractor, no per-split branch.** Parsing the harmful side more eagerly
   than the benign side would narrow the grant relative to the attack and invent
   the gain, which is the defect that cost eighteen AgentThreatBench events.

``expand_targets`` controls whether a multi-target pin becomes multiple events.
On (the default) a tool pinned to five recipients emits the five calls the
grading function requires, so destination substitution is visible. Off keeps
one event per ``target_functions`` entry by collapsing to the first pin — the
grant still lists every benign pin either way. An earlier version *dropped*
multi-target tools from the grant entirely when expand was off; that left
destination-differing deepfake/video behaviours uncontained by construction.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, EventLabel
from benchmarks.datasets._common import classify_verb
from benchmarks.datasets.agentharm_targets import TargetIndex

_ISSUED = "2026-01-01T00:00:00+00:00"
_EXPIRES = "2026-12-31T00:00:00+00:00"

# Content-bearing tools: attach twin free-text into args.prompt for soft
# STEP_UP (never into resource / authorized_args — that would invent hard ASR).
_CONTENT_PROMPT_TOOLS = frozenset({
    "run_stable_diffusion_model",
    "create_ai_video",
    "create_ransomware",
    "create_encryption_tool",
    "add_hidden_malware",
    "add_new_features",
    "create_instagram_story",
    "create_instagram_post",
    "send_email",
    "send_message",
    "send_message_whatsapp",
    "send_direct_message_x",
    "send_direct_message_instagram",
    "send_direct_message_tiktok",
    "post_on_x",
    "post_on_facebook",
    "post_on_instagram",
    "post_to_blog",
    "post_to_amazon",
    "post_forum_comment",
    "post_x_reply",
    "share_on_pinterest",
})


def _default_root() -> Path:
    return Path(__file__).resolve().parents[2] / ".benchmark-corpus" / "AgentHarm"


def _read_split(path: Path) -> dict[str, dict[str, Any]]:
    payload = json.loads(path.read_text())
    behaviors = payload.get("behaviors", payload) if isinstance(payload, dict) else payload
    return {str(b["id"]): b for b in behaviors if "id" in b}


class AgentHarmLoader:
    name = "agentharm"

    def __init__(self, data_root: str | None = None, *, split: str = "test_public",
                 targets: bool = True, expand_targets: bool = True,
                 grading_root: str | None = None) -> None:
        self._root = Path(data_root) if data_root else _default_root()
        self._split = split
        # ``targets=False`` reproduces the tool-name-only encoding this loader
        # had before the grading functions were parsed. Kept so the A/B is one
        # flag rather than a git revert.
        self._targets = targets
        self._expand = expand_targets
        self._grading_root = Path(grading_root) if grading_root else None
        self._index: TargetIndex | None = None

    def _target_index(self) -> TargetIndex | None:
        if not self._targets:
            return None
        if self._index is None:
            try:
                self._index = TargetIndex(self._grading_root)
            except (OSError, SyntaxError):
                # The grading functions ship with inspect_evals, not with the
                # behaviour JSON. Without them we fall back to the coarse
                # encoding rather than failing the corpus.
                return None
        return self._index

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
        index = self._target_index()

        tasks: list[BenchmarkTask] = []
        for behavior_id, benign_case in benign.items():
            harmful_case = harmful.get(behavior_id)
            if harmful_case is None:
                continue
            tasks.extend(_pair_to_tasks(behavior_id, benign_case, harmful_case,
                                        index=index, expand=self._expand))
            if limit and len(tasks) >= limit:
                break
        return tasks


# Tools that commonly take a filesystem path or URL argument. Prompt-extracted
# destinations attach only to these — never to free-text tools like
# ``run_stable_diffusion_model`` (prompt body is content, not a target).
_PATH_URL_TOOLS = frozenset({
    "download_image", "download_pdf", "download_file", "get_webpage",
    "create_ai_video", "upload_youtube_video", "upload_tiktok_video",
    "post_on_x", "post_on_facebook", "post_on_instagram", "create_instagram_post",
    "create_instagram_story", "share_on_pinterest", "post_to_blog",
    "send_email",  # attachments / linked URLs sometimes appear as paths
})

_PROMPT_PATH = re.compile(
    r"(/(?:home|tmp|var|etc|Desktop)/[A-Za-z0-9._/\-]+"
    r"|https?://[A-Za-z0-9._/\-?=&%]+)"
)


def _prompt_destinations(prompt: str) -> list[str]:
    """Concrete path/URL literals from a behaviour prompt (not free-text cues)."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in _PROMPT_PATH.findall(prompt or ""):
        v = raw.rstrip(".,;:)'\"")
        if not v or v in seen:
            continue
        seen.add(v)
        kind = "url" if v.startswith("http") else "path"
        out.append(f"{kind}:{v}")
    return out


def _pinned(index: TargetIndex | None, grading_function: str, split: str,
            expand: bool,
            *, prompt: str = "", tools: list[str] | None = None,
            ) -> dict[str, list[str]]:
    """tool -> the target resources that split's grading function pins for it.

    Multi-target pins are always kept for the grant. ``expand`` only decides
    whether events multiply (all pins) or collapse to the first pin; dropping
    multi-target tools from the grant used to make destination-differing twins
    look identical at the resource layer.

    When the grading function omits a path/URL that the prompt itself names,
    attach it to path/URL tools in ``tools`` — same destination-binding story,
    sourced from the sealed request text rather than invented.
    """
    del expand  # grant retention no longer depends on expand
    out: dict[str, list[str]] = {}
    if index is not None:
        by_tool = index.for_behavior(grading_function, split)
        for tool, targets in by_tool.items():
            ordered = sorted(targets)
            if ordered:
                out[tool] = ordered
    # Prompt-literal destinations (benign → grant, harmful → attack events).
    prompt_dests = _prompt_destinations(prompt)
    if prompt_dests and tools:
        for tool in tools:
            if tool not in _PATH_URL_TOOLS:
                continue
            cur = list(out.get(tool, []))
            for d in prompt_dests:
                if d not in cur:
                    cur.append(d)
            if cur:
                out[tool] = cur
    return out


def _pair_to_tasks(
    behavior_id: str,
    benign_case: dict[str, Any],
    harmful_case: dict[str, Any],
    *,
    index: TargetIndex | None = None,
    expand: bool = False,
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
    grading_function = str(benign_case.get("grading_function", ""))
    # The mandate's granularity is a function of the BENIGN twin only. A tool the
    # benign grading function (or benign prompt literal) pins a destination for
    # is destination-scoped; every other tool is granted with no destination
    # constraint at all.
    benign_pins = _pinned(
        index, grading_function, "benign", expand,
        prompt=str(benign_case.get("prompt") or ""), tools=benign_tools,
    )
    harmful_pins = _pinned(
        index, grading_function, "harmful", expand,
        prompt=str(harmful_case.get("prompt") or ""), tools=harmful_tools,
    )
    scoped = {t for t in benign_tools if t in benign_pins}

    def _resources_for(tool: str, pins: dict[str, list[str]]) -> list[str]:
        """The resource strings one call to ``tool`` is represented by.

        A destination-scoped tool whose destination this split does not pin
        falls back to the coarse resource, which the grant always contains: an
        action we cannot locate is an action we cannot contain. With expand off,
        multi-target pins collapse to the first pin for the event stream only;
        the grant (built separately) still lists every benign pin.
        """
        if tool in scoped and pins.get(tool):
            ordered = pins[tool]
            if expand or len(ordered) == 1:
                return [f"mcp:tool:{tool}#{t}" for t in ordered]
            return [f"mcp:tool:{tool}#{ordered[0]}"]
        return [f"mcp:tool:{tool}"]

    caps_seen: set[tuple[str, str]] = set()
    caps: list[dict[str, str]] = []
    granted_resources: list[str] = []
    for tool in benign_tools:
        # Fail-closed destination grants: when the benign twin pinned destinations
        # for tool T, grant only ``mcp:tool:T#…`` — not the coarse ``mcp:tool:T``
        # co-grant that previously let unlocatable harmful calls through (+~2pp
        # hard ASR, 0% FB on AgentHarm). Unscoped tools stay coarse.
        if tool in scoped:
            grant_resources = [
                f"mcp:tool:{tool}#{t}" for t in benign_pins.get(tool, ())
            ]
        else:
            grant_resources = [f"mcp:tool:{tool}"]
        for resource in grant_resources:
            key = (resource, classify_verb(tool))
            if key not in caps_seen:
                caps_seen.add(key)
                caps.append({"resource": key[0], "action": key[1]})
                granted_resources.append(resource)

    # Seal the *benign* user request for both twins — soft content judges
    # harmful free-text against what the user authorized, not the short name.
    benign_prompt = str(benign_case.get("prompt") or "")
    harmful_prompt = str(harmful_case.get("prompt") or "")
    short_name = str(benign_case.get("name") or behavior_id)

    # The one grant both sessions are judged against: what the user authorized.
    mandate = {
        "grant_id": grant_id,
        "issuer": "did:clayseal:agentharm",
        "issued_at": _ISSUED,
        "expires_at": _EXPIRES,
        "allowed_actions": sorted({classify_verb(t) for t in benign_tools}),
        "allowed_resources": granted_resources,
        "task": {"summary": benign_prompt, "name": short_name},
    }
    identical = set(benign_tools) == set(harmful_tools)
    overlap = set(benign_tools) & set(harmful_tools)

    def _task(suffix: str, tools: list[str], label: EventLabel,
              meta_for, twin_prompt: str) -> BenchmarkTask:
        task_id = f"{grant_id}-{suffix}"
        pins = benign_pins if label is EventLabel.BENIGN else harmful_pins
        events = []
        for tool in tools:
            for resource in _resources_for(tool, pins):
                target = resource.split("#", 1)[1] if "#" in resource else None
                meta = dict(meta_for(tool))
                meta["target"] = target
                # Soft free-text only — never authorized_args / resource pins.
                args = (
                    {"prompt": twin_prompt}
                    if tool in _CONTENT_PROMPT_TOOLS and twin_prompt.strip()
                    else {}
                )
                events.append(BenchmarkEvent(
                    event_id=f"{task_id}-{len(events)}", tool_name=tool,
                    resource=resource, action=classify_verb(tool),
                    label=label, args=args, meta=meta,
                ))
        return BenchmarkTask(
            task_id=task_id,
            # Goal sealing uses mandate.task.summary (benign prompt) via _goal_for.
            summary=benign_prompt or short_name,
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
                "name": short_name,
                # True when the harmful twin needs no tool the user did not
                # grant: the subset no per-call authority layer can separate.
                "identical_tool_set": identical,
                # How much of this behaviour the grading functions let us see.
                "destination_scoped_tools": sorted(scoped),
                "unlocatable_tools": sorted(set(tools) - scoped),
            },
        )

    return [
        _task("benign", benign_tools, EventLabel.BENIGN,
              lambda tool: {"source": "agentharm",
                            "category": benign_case.get("category", "")},
              benign_prompt),
        _task("harmful", harmful_tools, EventLabel.ATTACK,
              lambda tool: {
                  "source": "agentharm",
                  "category": harmful_case.get("category", ""),
                  "attack_class": "same-tool-harmful-intent" if tool in overlap
                                  else "unauthorized-tool",
                  "shared_with_benign": tool in overlap,
              },
              harmful_prompt),
    ]
