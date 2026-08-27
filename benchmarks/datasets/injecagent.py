"""InjecAgent loader, indirect prompt-injection tool-attack corpus.

InjecAgent (Zhan et al.) frames each case as a user instruction plus an
attacker instruction smuggled through a tool's returned content, targeting
either data exfiltration or a direct harmful tool call. It maps onto the same
benign/attack event shape: the user's intended tool call is BENIGN; the
attacker's target tool call is ATTACK.

The corpus ships as JSON (test cases + a tool registry). Point ``data_root`` at
a local checkout; this loader is exercised on the Azure VM run alongside
AgentDojo. Implemented as a thin, well-marked stub so the dataset is wired into
the registry now and filled in against the pinned data layout on the VM.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, EventLabel


class InjecAgentLoader:
    name = "injecagent"

    def __init__(self, data_root: str | None = None) -> None:
        # Default to the checked-out corpus, the way every other loader does.
        # Requiring an explicit path meant the registry factory built a loader
        # that could never load, so the corpus stayed dark even once fetched.
        default = (Path(__file__).resolve().parents[2] / ".benchmark-corpus"
                   / "InjecAgent" / "data")
        self._data_root = Path(data_root) if data_root else default

    def load(self, *, limit: int | None = None) -> list[BenchmarkTask]:
        if self._data_root is None or not self._data_root.exists():
            raise RuntimeError(
                "InjecAgent data not found. Clone the corpus and pass its path: "
                "InjecAgentLoader(data_root='.../InjecAgent/data'). Wired for the "
                "Azure VM run; see benchmarks/README.md."
            )
        cases = _read_cases(self._data_root)
        tasks: list[BenchmarkTask] = []
        for i, case in enumerate(cases):
            task = _case_to_task(case, index=i)
            if task is not None:
                tasks.append(task)
            if limit and len(tasks) >= limit:
                break
        return tasks


# Fields this loader turns into events. `base` and `enhanced` differ ONLY in
# `Tool Response`, which wraps the injection in a stronger prompt, and that field
# is not one of these. Verified against the corpus: 510/510 dh cases and 544/544
# ds cases are identical on every field below.
_IDENTITY_FIELDS = ("User Tool", "Attacker Tools", "User Instruction",
                    "Attacker Instruction", "Attack Type")


def _read_cases(root: Path) -> list[dict[str, Any]]:
    """Every distinct scenario, once.

    Globbing `test_cases_*.json` reads base and enhanced and concatenates them,
    and since they agree on everything this loader uses, every scenario was
    emitted twice. The shipped figure of 2,108 tasks and 3,196 attack events is
    1,054 scenarios and 1,598 events, each counted twice, which doubles any
    per-event denominator and narrows every confidence interval by a factor of
    root two for free.

    The corpus is also a cross product rather than 1,054 authored scenarios: 17
    user cases against 30 direct-harm and 32 data-stealing attackers. 79 authored
    items in total.
    """
    cases: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    for path in sorted(root.glob("test_cases_*.json")):
        with path.open() as handle:
            payload = json.load(handle)
        if not isinstance(payload, list):
            continue
        for case in payload:
            key = tuple(json.dumps(case.get(f), sort_keys=True)
                        for f in _IDENTITY_FIELDS)
            if key in seen:
                continue
            seen.add(key)
            cases.append(case)
    return cases


# Verbs read from the TOOL NAME, both sides, identically.
#
# The previous rule was `"send" if "send" or "email" in the name else "write"`,
# applied only to attacker tools, while every benign tool was hard-coded to
# "read". The mandate allows "read" alone, so the label decided the verb and the
# verb decided containment: 100% on this corpus was our own labelling read back.
#
# 31 of the 32 data-stealing step-one attacker tools are data ACCESS calls
# (AmazonViewSavedAddresses, BankManagerGetAccountInformation,
# The23andMeDownloadData), and calling them "write" is simply wrong. InjecAgent
# tool names put the verb in the middle, so this matches anywhere in the name and
# checks the acquisition verbs first, since GitHubGetUserDetails is a read even
# though "Details" is not.
_VERB_MARKERS = (
    ("read", ("get", "view", "list", "search", "read", "fetch", "download",
              "retrieve", "query", "check", "find")),
    ("send", ("send", "email", "post", "share", "publish", "transfer", "pay")),
    ("delete", ("delete", "remove", "revoke")),
    ("write", ("create", "add", "grant", "update", "set", "write", "schedule",
               "book", "order", "unlock", "enable", "disable", "install")),
)


def _verb_of(tool: str) -> str:
    lowered = tool.lower()
    for verb, markers in _VERB_MARKERS:
        if any(m in lowered for m in markers):
            return verb
    return "call"


def _attacker_tools(case: dict[str, Any]) -> list[str]:
    raw = case.get("Attacker Tools") or case.get("Attacker Tool") or case.get("attacker_tool")
    if isinstance(raw, str):
        return [raw] if raw else []
    if isinstance(raw, (list, tuple)):
        return [str(t) for t in raw if t]
    return []


def _case_to_task(case: dict[str, Any], *, index: int) -> BenchmarkTask | None:
    user_tool = str(case.get("User Tool") or case.get("user_tool") or "")
    attacker_tools = _attacker_tools(case)
    if not user_tool or not attacker_tools:
        return None
    benign = BenchmarkEvent(
        event_id=f"injec-{index}-b", tool_name=user_tool,
        resource=f"mcp:tool:{user_tool}", action=_verb_of(user_tool),
        label=EventLabel.BENIGN, meta={"source": "injecagent"},
    )
    # Each attacker tool the injection would invoke is an out-of-scope action.
    attack = [
        BenchmarkEvent(
            event_id=f"injec-{index}-a{j}", tool_name=tool,
            resource=f"mcp:tool:{tool}",
            action=_verb_of(tool),
            label=EventLabel.ATTACK,
            meta={"source": "injecagent", "attack": case.get("Attack Type", "")},
        )
        for j, tool in enumerate(attacker_tools)
    ]
    return BenchmarkTask(
        task_id=f"injecagent-{index}",
        summary=str(case.get("User Instruction", "")),
        events=[benign, *attack],
        # LEAST PRIVILEGE, and this is the whole result on this corpus.
        #
        # InjecAgent's own harness grants the agent the attacker's tools:
        # `available_tool_names = [item['User Tool']] + item['Attacker Tools']`
        # (src/evaluate_prompted_agent.py). It has to, because it measures whether
        # the MODEL is talked into calling them. We grant only the tool the user's
        # task needs, which is what an authorization layer would issue.
        #
        # So our containment on this corpus is that narrowness and nothing else.
        # Measured under the corpus's own grant, the whole ladder falls from 100%
        # to 0.0%: every attacker tool is authorized, every call carries no target
        # and no arguments, and there is nothing left for any rung to check.
        #
        # Both numbers are true and they answer different questions. Ours says
        # least privilege alone defeats this attack class. The corpus's says that
        # once the tool is granted we contain none of it. Quoting the first
        # without the second would be the ASB mistake with a bigger denominator.
        allowed_tools={user_tool},
        capabilities=[{"resource": f"mcp:tool:{user_tool}",
                       "action": _verb_of(user_tool)}],
        mandate={
            "grant_id": f"injec-grant-{index}",
            "issuer": "did:clayseal:injecagent",
            "issued_at": "2026-07-21T00:00:00+00:00",
            "expires_at": "2026-07-22T00:00:00+00:00",
            # The verb the user's own tool performs, not a hardcoded "read".
            # Hardcoding it meant a benign tool our classifier calls `call` was
            # refused by its own mandate: 5.88% false blocks against a grant that
            # was supposed to authorize exactly that call.
            "allowed_actions": [_verb_of(user_tool)],
            "allowed_resources": [f"mcp:tool:{user_tool}"],
        },
        meta={
            "source": "injecagent",
            "attack_type": str(case.get("Attack Type", "")),
            # What the corpus itself would have granted, so a scorer can measure
            # the other reading without re-deriving it.
            "corpus_granted_tools": sorted({user_tool, *attacker_tools}),
            "containment_is_least_privilege": True,
        },
    )
