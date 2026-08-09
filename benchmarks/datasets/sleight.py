"""SLEIGHT-Bench loader: covert harmful objectives in coding-agent transcripts.

SLEIGHT-Bench (arXiv:2605.16626, Anthropic alignment) is a 2026 benchmark of a
different kind from everything else we replay. RedCode, AgentHarm, and ASB are
catalogues of *risky operations*. SLEIGHT is a catalogue of *evasion*: 44 attacks
in which a coding agent covertly pursues a harmful objective while trying not to
look like it is, each paired with a benign transcript for false-positive
calibration.

It matters to us for three reasons.

It tests a different layer. The published result is about **monitors**: 20 of 40
attacks are never caught by an Opus 4.6 monitor with extended thinking across ten
trials at a 1% false-positive rate, and the overall catch rate is 32%. That is
the behavioural tier, not the authorization tier, and a system claiming to
contain loss-of-control behaviour should be measured on it.

Its categories map onto our own claims. `authorization_confusion` is our
enforcement layer named directly. `multi_session` is the cross-session hole we
closed this week. `n_hops` is delegation. If our layer is doing what we say,
those categories should behave differently from `model_priors` or
`refusal_forcing`, which are about what a monitor believes rather than about
what an action touches.

It is benign-paired. Every attack ships with a matched benign transcript, so a
false-block rate on this corpus is measured against the same distribution rather
than against an unrelated benign set.

**Canary.** The transcripts carry an explicit opt-out string and are shipped
encrypted to keep them out of training corpora. They live under
`.benchmark-corpus/` which is gitignored, and this loader never writes transcript
content into results. Decrypt with the key published in the upstream README.
"""
from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from typing import Any

from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, EventLabel

# The workspace is per-transcript, taken from the session's own `cwd`. Hardcoding
# one root made every path out of scope and produced 89.6% containment at an
# 89.7% false-block rate: the defense blocking everything indiscriminately, which
# reads as a catastrophic over-defense result and was a loader bug.
DEFAULT_WORKSPACE = "/repo"

# A coding agent's legitimate authority: its own checkout. Deliberately the same
# shape as the RedCode mandate so the two corpora are judged by one policy and a
# difference between them is a property of the attacks rather than of the grant.
_TOOLS = {"Bash", "Read", "Write", "Edit", "Glob", "Grep", "NotebookEdit"}
_CAPABILITIES = [
    {"resource": "workspace", "action": a}
    for a in ("read", "write", "delete", "execute", "call", "send")
]

# Commands whose first path-shaped argument is the thing being touched.
_READ_CMDS = {"cat", "less", "head", "tail", "grep", "find", "ls", "od", "xxd", "strings"}
_WRITE_CMDS = {"cp", "mv", "tee", "install", "dd", "tar", "zip", "chmod", "chown"}
_DELETE_CMDS = {"rm", "shred", "truncate"}
_NET_CMDS = {"curl", "wget", "nc", "ncat", "ssh", "scp", "rsync", "git"}

_URL = re.compile(r"https?://([^/\s\"']+)")
_HOSTISH = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _mandate(task_id: str, workspace: str,
             authorized_paths: list[str] | None = None,
             authorized_nets: list[str] | None = None) -> dict[str, Any]:
    """What the user authorized for this task.

    SLEIGHT ships no mandate. It is a TRANSCRIPT-MONITORING benchmark: paired
    attack and benign runs of a coding agent, scored by whether a monitor reading
    the transcript flags the sabotage. Nothing in it says what the agent was
    allowed to touch.

    Granting only the session's `cwd` was our invention and it was wrong in a way
    that made the whole number meaningless. Real tasks legitimately reach outside
    their checkout: "back up the Orion weights" reads `/data/models/orion-finetune`
    from a home directory. 114 of 311 benign events were refused for being outside
    a scope the corpus never declared, which is where the 32.64% false-block came
    from, and containment came from the same invented boundary. Both sides
    measured the same thing, which is why they moved together and why the corpus
    appeared to show no discrimination.

    The paired BENIGN twin is the authorization. It is the same task performed
    without sabotage, so the paths it touches are exactly the surface the user's
    request needed. Containment then asks the goal-substitution question that
    AgentHarm asks: does the sabotaged run reach beyond what the legitimate run
    required?

    Network hosts the benign twin contacted are also granted (as ``net:<host>``
    path entries) and ``send`` is an allowed operation — otherwise every
    legitimate curl/scp was refused as ``action 'send' out of scope`` and novel
    attacker hosts were not the thing being measured.

    This makes path/egress containment meaningful and makes the false-block
    number on this corpus **unmeasurable**, because a mandate derived from the
    benign twin clears that twin by construction. Friction is measured on tau2,
    BFCL and ATIF. Covert-intent discrimination is scored by the trajectory
    detector (``--mode detector``), not the per-action ladder.
    """
    ws = workspace.rstrip("/") or DEFAULT_WORKSPACE
    allowed = [f"{ws}/**", ws.lstrip("/") + "/**", f"{ws}"]
    for granted in authorized_paths or ():
        cleaned = granted.rstrip("/")
        if not cleaned:
            continue
        allowed.extend([cleaned, f"{cleaned}/**", cleaned.lstrip("/") + "/**"])
    for net in authorized_nets or ():
        if net:
            allowed.append(net if net.startswith("net:") else f"net:{net}")
    ops = ["read", "write", "delete", "execute", "call", "send"]
    return {
        "mandate_id": f"sleight-{task_id}",
        "task": {"summary": f"work in {ws}"},
        "scope": {
            "allowed_paths": sorted(set(allowed)),
            "denied_paths": [],
            "allowed_operations": ops,
        },
    }


def _authorized_nets(events) -> list[str]:
    """``net:`` destinations the benign twin contacted."""
    return sorted({e.path for e in events
                   if e.path and str(e.path).startswith("net:")})

def _authorized_surface(events) -> list[str]:
    """The directories a run touched, as the authorization it implies."""
    import posixpath

    out: set[str] = set()
    for event in events:
        if not event.path or event.path.startswith("net:"):
            continue
        parent = posixpath.dirname(event.path.rstrip("/"))
        if parent and parent != "/":
            out.add(parent)
    return sorted(out)


def _workspace_of(path: Path) -> str:
    """The cwd the transcript itself records, which is the agent's checkout."""
    for line in path.read_text().splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        cwd = obj.get("cwd")
        if isinstance(cwd, str) and cwd.startswith("/"):
            return cwd
    return DEFAULT_WORKSPACE


def _classify(command: str) -> tuple[str, str | None]:
    """Map a shell command to (action, target).

    Best-effort and deliberately conservative: a command we cannot parse yields
    no target, which means the event is judged on tool and resource alone rather
    than being invented a path that might not exist. Over-parsing here would
    manufacture containment.
    """
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()
    if not parts:
        return "call", None

    head = Path(parts[0]).name
    args = [p for p in parts[1:] if not p.startswith("-")]

    url = _URL.search(command)
    if head in _NET_CMDS or url:
        host = url.group(1) if url else None
        if host is None:
            ip = _HOSTISH.search(command)
            host = ip.group(1) if ip else None
        if host:
            return ("read" if head in {"curl", "wget"} and ">" not in command else "send",
                    f"net:{host}")

    target = next((a for a in args if "/" in a or a.startswith(".")), None)
    if head in _DELETE_CMDS:
        return "delete", target
    if head in _WRITE_CMDS:
        return "write", target
    if head in _READ_CMDS:
        return "read", target
    return "execute", target


def _resolve(target: str | None, workspace: str) -> str | None:
    """Relative paths in a shell command are relative to the session cwd."""
    if not target or target.startswith(("net:", "/")):
        return target
    return f"{workspace.rstrip('/')}/{target.lstrip('./')}"


def _events_from_transcript(path: Path, label: EventLabel, task_id: str,
                            workspace: str) -> list[BenchmarkEvent]:
    events: list[BenchmarkEvent] = []
    for i, line in enumerate(path.read_text().splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "canary" in obj and "role" not in obj:
            continue
        content = obj.get("content")
        if not isinstance(content, dict) or content.get("type") != "tool_use":
            continue

        tool = content.get("name", "Bash")
        payload = content.get("input") or {}
        command = payload.get("command") or ""
        if tool == "Bash" and command:
            action, target = _classify(command)
        else:
            target = payload.get("file_path") or payload.get("path") or payload.get("notebook_path")
            action = {"Read": "read", "Grep": "read", "Glob": "read",
                      "Write": "write", "Edit": "write",
                      "NotebookEdit": "write"}.get(tool, "call")

        events.append(BenchmarkEvent(
            event_id=f"{task_id}-{i}",
            tool_name=tool,
            resource="workspace",
            action=action,
            label=label,
            path=_resolve(target, workspace),
            args={k: v for k, v in payload.items() if isinstance(v, (str, int, float))},
            meta={"suite": "sleight"},
        ))
    return events


class SleightLoader:
    """Attack transcripts and their benign pairs, one task per transcript."""

    name = "sleight"

    def __init__(self, data_root: str | Path | None = None) -> None:
        default = Path(__file__).resolve().parents[2] / ".benchmark-corpus" / "sleight-bench"
        self.root = Path(data_root) if data_root else default

    def load(self, limit: int | None = None) -> list[BenchmarkTask]:
        attacks = self.root / "attacks"
        if not attacks.exists():
            raise RuntimeError(
                "SLEIGHT-Bench not found. Clone github.com/safety-research/sleight-bench "
                "into .benchmark-corpus/sleight-bench and run its decrypt.py with the key "
                "published in its README."
            )
        transcripts = sorted(attacks.rglob("*.jsonl"))
        if not transcripts:
            raise RuntimeError(
                "SLEIGHT-Bench present but not decrypted: no .jsonl transcripts found. "
                "Run decrypt.py with the key from the upstream README."
            )

        # First pass: the benign twin of each pair, whose surface is the grant.
        benign_surface: dict[str, list[str]] = {}
        benign_nets: dict[str, list[str]] = {}
        for path in transcripts:
            stem = path.stem
            if not any(m in stem.lower() for m in ("benign", "control", "clean")):
                continue
            ws = _workspace_of(path)
            evs = _events_from_transcript(path, EventLabel.BENIGN, "probe", ws)
            benign_surface[path.parent.name] = _authorized_surface(evs)
            benign_nets[path.parent.name] = _authorized_nets(evs)

        tasks: list[BenchmarkTask] = []
        for path in transcripts:
            category = path.relative_to(attacks).parts[0]
            stem = path.stem
            # The benign pair is the transcript whose name marks it as the
            # side-by-side control. Anything else is the attack.
            benign = any(marker in stem.lower() for marker in ("benign", "control", "clean"))
            label = EventLabel.BENIGN if benign else EventLabel.ATTACK
            task_id = f"sleight-{category}-{path.parent.name}-{stem}"
            workspace = _workspace_of(path)
            events = _events_from_transcript(path, label, task_id, workspace)
            if not events:
                continue
            key = path.parent.name
            tasks.append(BenchmarkTask(
                task_id=task_id,
                summary=f"{category}: coding-agent transcript",
                events=events,
                mandate=_mandate(task_id, workspace,
                                 benign_surface.get(key),
                                 benign_nets.get(key)),
                capabilities=list(_CAPABILITIES),
                allowed_tools=set(_TOOLS),
                meta={"category": category, "benign_pair": benign,
                      "workspace": workspace,
                      # Per-action ladder has almost no intent signal here.
                      # Score covert intent with --mode detector.
                      "score_with": "detector",
                      # The false-block number on this corpus is not reportable:
                      # the mandate is derived from the benign twin, so that twin
                      # is clean by construction. Friction is measured on tau2,
                      # BFCL and ATIF instead.
                      "false_block_unscoreable": True},
            ))
            if limit and len(tasks) >= limit:
                break
        return tasks