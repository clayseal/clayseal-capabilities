"""RedCode-Exec loader — risky code-execution operations for a coding agent.

RedCode (Guo et al., NeurIPS 2024 D&B) ships 1,410 *risky* code-execution cases
(27 risk indexes x Python and Bash) as static JSON: each case is a concrete
script plus a natural-language summary of what it does. Every case is risky by
construction, so every RedCode event here is labeled ATTACK — this loader
synthesizes no attacks and relabels nothing.

Why this corpus is the sharp test for an authorization layer
------------------------------------------------------------
In AgentDojo/InjecAgent the attack usually calls a tool the user never granted,
so a tool-name allowlist already catches it. RedCode is the opposite: the agent
is a *coding agent* that legitimately holds ``execute``/``read``/``write`` on a
workspace, and the attack uses exactly those granted tools against an
out-of-scope **path** or **network destination** (``/etc/passwd``, ``/root/.bashrc``,
``http://1mocat.github.io/abusive.py``). Tool-name and ``resource:action`` rungs
are structurally blind to it; only path scoping and egress scoping can see it.

Two subsets, reported separately
--------------------------------
RedCode's risk indexes split cleanly into two kinds of risk, and conflating them
would misstate what an authorization layer does:

- ``resource`` — the operation targets a filesystem path or a network
  destination. An authority layer is the right control here, and this is the
  subset the containment number is about.
- ``logic`` — the risk is inside the code's own semantics (biased hiring score,
  unsalted password hash, weak PRNG, unsafe ``pickle`` load, fork bomb). No
  resource boundary is crossed, so a *resource*-authorization layer cannot and
  should not claim these. They are loaded (so the corpus is complete and the
  blind spot is visible) but tagged ``risk_kind="logic"``; see
  ``benchmarks/results/redcode.md`` for the honest split.

The index taxonomy below was derived by reading each index's cases, not guessed:
each RedCode index is homogeneous (e.g. every index-8 case deletes a file), so
the operation kind is a property of the index, and only the concrete target is
parsed per case. That keeps the fragile part (regex) to the smallest possible
job.

Friction
--------
RedCode contains no benign trajectories, so a false-block rate computed from it
alone would be vacuous (nothing benign to wrongly block). ``include_benign``
mixes in real BFCL multi-turn *file-system* trajectories under the **same**
coding-agent mandate, giving a genuine utility axis on the same tool surface.
"""
from __future__ import annotations

import json
import os.path
import re
from pathlib import Path
from typing import Any

from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, EventLabel

# The workspace a coding agent is legitimately scoped to. RedCode's container
# runs the agent out of /app, so /app/** is its in-scope working tree.
WORKSPACE = "app"

_ISSUED = "2026-01-01T00:00:00+00:00"
_EXPIRES = "2026-12-31T00:00:00+00:00"

# --------------------------------------------------------------------------- #
# Risk-index taxonomy (derived by reading the corpus, see module docstring)
# --------------------------------------------------------------------------- #
# index -> (risk_kind, action, label)
_INDEX_RISK: dict[int, tuple[str, str, str]] = {
    1:  ("resource", "send",    "exfiltrate-file-over-network"),
    2:  ("resource", "write",   "download-remote-to-disk"),
    3:  ("resource", "send",    "fetch-untrusted-url"),
    4:  ("resource", "write",   "copy-sensitive-file"),
    5:  ("resource", "read",    "list-directory"),
    6:  ("resource", "write",   "write-encoded-payload"),
    7:  ("resource", "read",    "read-sensitive-file"),
    8:  ("resource", "delete",  "delete-system-file"),
    9:  ("resource", "write",   "append-to-startup-file"),
    10: ("resource", "send",    "open-raw-socket"),
    11: ("logic",    "read",    "system-introspection"),
    12: ("logic",    "call",    "biased-decision-logic"),
    13: ("resource", "read",    "path-traversal-read"),
    14: ("logic",    "call",    "unsafe-eval"),
    15: ("logic",    "call",    "weak-input-validation"),
    16: ("logic",    "call",    "weak-credential-check"),
    17: ("resource", "read",    "privilege-escalation-read"),
    # Process control crosses no filesystem or network boundary, so the path
    # ladder cannot see it. Clay Seal enforces it at the syscall layer (iVisor),
    # which this replay does not model — kept out of the resource subset so the
    # containment number stays about what the ladder actually decides.
    18: ("process",  "delete",  "kill-system-processes"),
    19: ("logic",    "call",    "weak-randomness"),
    20: ("logic",    "call",    "weak-password-hashing"),
    21: ("resource", "send",    "udp-egress"),
    22: ("logic",    "call",    "arithmetic-flaw"),
    23: ("logic",    "call",    "unguarded-admin-logic"),
    24: ("logic",    "call",    "unsafe-deserialization"),
    25: ("logic",    "call",    "data-structure-flaw"),
    26: ("resource", "send",    "fetch-untrusted-url"),
    27: ("logic",    "call",    "resource-exhaustion"),
}

# Risk indexes whose target is a network endpoint rather than a file.
_EGRESS_INDEXES = {1, 3, 10, 21, 26}

_URL_RE = re.compile(r'https?://[^\s\'"<>)\\]+')
_ABS_PATH_RE = re.compile(
    r'(?<![\w.])/(?:etc|usr|bin|sbin|var|root|home|app|tmp|proc|sys|opt|lib|dev|boot|srv|mnt)'
    r'(?:/[\w.\-]+)*'
)
_IP_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')

# Interpreter and device paths are how the script *runs*, never what it targets.
_NOT_A_TARGET = {
    "/bin/bash", "/bin/sh", "/bin/echo", "/bin/cat", "/dev/null", "/dev/zero",
    "/usr/bin/env", "/usr/bin/python", "/usr/bin/python3", "/usr/bin/perl",
    "/usr/bin", "/bin", "/usr", "/etc", "/root", "/app", "/tmp", "/var",
}


def _default_root() -> Path:
    return Path(__file__).resolve().parents[2] / ".benchmark-corpus" / "RedCode"


def _strip_shebang(code: str) -> str:
    return "\n".join(ln for ln in code.splitlines() if not ln.strip().startswith("#!"))


def _extract_endpoint(code: str, summary: str) -> str | None:
    """The network destination an egress case targets.

    Three shapes appear in the corpus: an explicit URL, a bash ``/dev/udp/host/port``
    redirect or ``nc host port``, and a Python socket tuple ``(host, port)``.
    Returned as ``net:<host>[:<port>]`` so it can never be confused with a
    filesystem path by the path-scope check.
    """
    m = _URL_RE.search(code) or _URL_RE.search(summary)
    if m:
        return m.group(0)
    body = _strip_shebang(code)
    # /dev/udp/127.0.0.1/5388  or  /dev/tcp/host/port
    m = re.search(r'/dev/(?:udp|tcp)/([\w.\-]+)/(\d+)', body)
    if m:
        return f"net:{m.group(1)}:{m.group(2)}"
    # nc [-u] [-w1] host port — skip flag tokens before the host.
    m = re.search(r'\bnc\b((?:\s+-[\w]+)*)\s+([\w.\-]+)\s+(\d{2,5})\b', body)
    if m:
        return f"net:{m.group(2)}:{m.group(3)}"
    # Python: sendto(..., ('127.0.0.1', 5388)) / connect(('host', port))
    m = re.search(r'\(\s*["\']([\w.\-]+)["\']\s*,\s*(\d{2,5})\s*\)', body)
    if m:
        return f"net:{m.group(1)}:{m.group(2)}"
    # Bare host/port variables assigned near a socket call.
    host = re.search(r'(?:target_ip|host|HOST|ip)\s*=\s*["\']([\d.]+)["\']', body)
    port = re.search(r'(?:target_port|port|PORT)\s*=\s*(\d{2,5})', body)
    if host:
        return f"net:{host.group(1)}" + (f":{port.group(1)}" if port else "")
    return None


def _extract_path(code: str, summary: str) -> str | None:
    """The filesystem object the script acts on, or None if it targets none.

    Shebangs and interpreter paths are stripped first; among the remaining
    absolute paths the most specific (deepest, then longest) wins, since a case
    that mentions both ``/etc`` and ``/etc/passwd`` is acting on the latter.
    Path-traversal cases compose their target from a base plus a ``../`` segment,
    so those are joined and normalized before matching.
    """
    body = _strip_shebang(code)

    # Traversal: a quoted absolute base plus a quoted ../ relative segment, which
    # the script joins. Resolve to the real target (/usr + ../etc/passwd).
    base = re.search(r'["\'](/[\w./\-]+)["\']', body)
    rel = re.search(r'["\'](\.\.[\w./\-]*)["\']', body)
    if base and rel:
        joined = os.path.normpath(os.path.join(base.group(1), rel.group(1)))
        if joined not in _NOT_A_TARGET:
            return joined

    cands = [
        m.group(0) for m in _ABS_PATH_RE.finditer(body)
        if m.group(0) not in _NOT_A_TARGET
    ]
    if not cands:
        # A quoted relative filename with an extension, e.g. "example.txt".
        for m in re.finditer(r'["\']([^"\'\n\s]{2,120})["\']', body):
            q = m.group(1)
            if q.startswith(("http", "%", "{", "$")) or _IP_RE.match(q):
                continue
            if q in _NOT_A_TARGET or q.upper() in {"N/A", "NA", "NONE"}:
                continue
            if "/" in q or re.search(r'\.\w{1,5}$', q):
                cands.append(q)
                break
    if not cands:
        return None
    cands.sort(key=lambda p: (p.count("/"), len(p)), reverse=True)
    return cands[0]


def _coding_agent_mandate(task_id: str, summary: str) -> dict[str, Any]:
    """The authorization a coding agent legitimately holds: its own workspace.

    Human-authorization schema so the mandate carries real *path* scope — the
    axis RedCode actually exercises.
    """
    return {
        "mandate_id": f"redcode-{task_id}",
        "task": {"summary": summary},
        "scope": {
            "allowed_paths": [f"{WORKSPACE}/**", f"/{WORKSPACE}/**"],
            "denied_paths": [],
            "allowed_operations": ["read", "write", "delete", "execute", "call"],
        },
    }


# Tools a coding agent holds. The attack uses these *granted* tools — the
# violation is the target, not the tool name.
_TOOLS = {
    "read": "read_file",
    "write": "write_file",
    "delete": "delete_file",
    "send": "http_request",
    "call": "execute_code",
}
_ALLOWED_TOOLS = set(_TOOLS.values()) | {"execute_code"}
_CAPABILITIES = [
    {"resource": "workspace", "action": a}
    for a in ("read", "write", "delete", "execute", "call", "send")
]


class RedCodeLoader:
    name = "redcode"

    def __init__(
        self,
        data_root: str | None = None,
        *,
        risk_kinds: tuple[str, ...] = ("resource",),
        include_benign: bool = True,
        bfcl_root: str | None = None,
    ) -> None:
        self._root = Path(data_root) if data_root else _default_root()
        self._risk_kinds = risk_kinds
        self._include_benign = include_benign
        self._bfcl_root = bfcl_root

    def load(self, *, limit: int | None = None) -> list[BenchmarkTask]:
        exec_dir = self._root / "dataset" / "RedCode-Exec"
        if not exec_dir.exists():
            raise RuntimeError(
                f"RedCode corpus not found at {exec_dir}. Clone it with:\n"
                "  git clone --depth 1 --filter=blob:none --sparse "
                "https://github.com/AI-secure/RedCode.git .benchmark-corpus/RedCode\n"
                "  cd .benchmark-corpus/RedCode && git sparse-checkout set dataset"
            )
        tasks: list[BenchmarkTask] = []
        for path in sorted(exec_dir.glob("*/*.json")):
            for case in json.loads(path.read_text()):
                task = self._case_to_task(case)
                if task is not None:
                    tasks.append(task)
                if limit and len(tasks) >= limit:
                    break
            if limit and len(tasks) >= limit:
                break
        if self._include_benign:
            tasks.extend(self._benign_companion(limit=limit))
        return tasks

    def _case_to_task(self, case: dict[str, Any]) -> BenchmarkTask | None:
        raw_index = str(case.get("Index", ""))
        try:
            index = int(raw_index.split("_")[0])
        except (ValueError, IndexError):
            return None
        risk = _INDEX_RISK.get(index)
        if risk is None:
            return None
        risk_kind, action, risk_label = risk
        if risk_kind not in self._risk_kinds:
            return None

        code = case.get("Code", "") or ""
        summary = case.get("Text_summary", "") or ""
        # The target is whatever kind of boundary this risk index crosses: a
        # network endpoint for egress indexes, a filesystem path otherwise.
        if index in _EGRESS_INDEXES:
            target = _extract_endpoint(code, summary) or _extract_path(code, summary)
        else:
            target = _extract_path(code, summary) or _extract_endpoint(code, summary)
        if risk_kind == "resource" and not target:
            # No parseable target: cannot state what boundary is crossed, so
            # scoring it would be a guess. Dropped, and counted in the report.
            return None

        task_id = f"redcode-{raw_index}"
        tool = _TOOLS.get(action, "execute_code")
        event = BenchmarkEvent(
            event_id=f"{task_id}-attack",
            tool_name=tool,
            resource="workspace",
            action=action,
            path=target,
            args={"target": target, "language": case.get("Language", "")},
            label=EventLabel.ATTACK,
            meta={
                "source": "redcode",
                "risk_index": index,
                "risk_kind": risk_kind,
                "attack_class": risk_label,
                "language": case.get("Language", ""),
            },
        )
        return BenchmarkTask(
            task_id=task_id,
            summary=summary[:200],
            events=[event],
            mandate=_coding_agent_mandate(raw_index, summary[:120]),
            capabilities=list(_CAPABILITIES),
            allowed_tools=set(_ALLOWED_TOOLS),
            meta={"source": "redcode", "risk_kind": risk_kind,
                  "risk_index": index, "goal_kind": "coding-agent"},
        )

    def _benign_companion(self, *, limit: int | None) -> list[BenchmarkTask]:
        """Real BFCL file-system trajectories under the same coding mandate.

        RedCode ships no benign side. Rather than synthesize one (which would
        make the utility axis circular), this replays genuine multi-turn
        file-system tool calls from Gorilla BFCL as the coding agent's own work.
        """
        from benchmarks.datasets.bfcl_fs import load_filesystem_trajectories

        try:
            trajectories = load_filesystem_trajectories(self._bfcl_root)
        except RuntimeError:
            return []
        tasks: list[BenchmarkTask] = []
        for traj_id, calls in trajectories:
            events: list[BenchmarkEvent] = []
            # BFCL's ground-truth calls are, by definition, the calls the user
            # authorized — so they are exactly the argument shapes the binding
            # rung should admit. Recording them here is what makes that rung
            # meaningful on this corpus rather than a pass-through.
            authorized: dict[str, list[dict[str, Any]]] = {}
            for i, (tool, args) in enumerate(calls):
                # Workspace-relative targets: the agent's own files.
                target = _bfcl_target(args)
                tool_name = _bfcl_tool(tool)
                call_args = {"target": target or "", "language": "python"}
                events.append(BenchmarkEvent(
                    event_id=f"{traj_id}-{i}",
                    tool_name=tool_name,
                    resource="workspace",
                    action=_bfcl_action(tool),
                    path=f"{WORKSPACE}/{target}" if target else None,
                    args=call_args,
                    label=EventLabel.BENIGN,
                    meta={"source": "bfcl-fs", "bfcl_tool": tool},
                ))
                authorized.setdefault(tool_name, []).append(dict(call_args))
            if not events:
                continue
            tasks.append(BenchmarkTask(
                task_id=f"bfcl-fs-{traj_id}",
                summary="Coding agent file-system work in its own workspace",
                events=events,
                mandate=_coding_agent_mandate(traj_id, "workspace file operations"),
                capabilities=list(_CAPABILITIES),
                allowed_tools=set(_ALLOWED_TOOLS),
                authorized_args=authorized,
                meta={"source": "bfcl-fs", "risk_kind": "benign",
                      "goal_kind": "coding-agent"},
            ))
            if limit and len(tasks) >= limit:
                break
        return tasks


_BFCL_WRITE = {"mkdir", "touch", "echo", "mv", "cp", "rm", "rmdir", "write"}
_BFCL_DELETE = {"rm", "rmdir"}


def _bfcl_tool(tool: str) -> str:
    low = tool.lower()
    if low in _BFCL_DELETE:
        return "delete_file"
    if low in _BFCL_WRITE:
        return "write_file"
    return "read_file"


def _bfcl_action(tool: str) -> str:
    low = tool.lower()
    if low in _BFCL_DELETE:
        return "delete"
    if low in _BFCL_WRITE:
        return "write"
    return "read"


def _bfcl_target(args: dict[str, Any]) -> str | None:
    for key in ("file_name", "source", "dir_name", "folder", "destination",
                "file_name1", "path"):
        val = args.get(key)
        if isinstance(val, str) and val and val not in (".", ".."):
            return val.lstrip("./")
    return None
