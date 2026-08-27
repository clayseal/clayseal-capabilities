"""DRIFT-shaped gate (arXiv:2506.12104) for the BPL live harness.

Published design (mechanism reproduction):
1. Secure planner: build an initial tool/privilege plan from the *user query
   alone* (injection isolator: tool returns never reach the planner).
2. Dynamic validator: allow on-plan calls; for off-plan calls, decide whether
   the deviation still complies with user intent / privilege limits.
3. Injection isolator: consequential args that appear only in prior tool
   returns (and not in the user query) are denied.

DRIFT's exception path in the published system fails open on validator
uncertainty; this reproduction fails open only for observe-class tools and
fails closed for consequential off-plan / tainted calls.

No session-level value budget. Prompt-specified multi-pay sequences stay on-plan.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_TOKEN = re.compile(r"[A-Za-z0-9_.:@/+-]{3,}")
_EDGE = ".:,;!?/+-_@"
_MONEY = re.compile(r"\$?\d{1,3}(?:,\d{3})+(?:\.\d+)?|\$\d+(?:\.\d+)?|\b\d+(?:\.\d+)?\b")

_CRITICAL = re.compile(
    r"(pay|send|transfer|delete|grant|approve|execute|ship|operate|export|"
    r"release|wire|refund|post_message|write_file)",
    re.IGNORECASE,
)
_OBSERVE = re.compile(
    r"^(list_|read_|get_|search_|load_|fetch_|check_|lookup_|find_|query_)",
    re.IGNORECASE,
)


def _norm(s: str) -> str:
    return str(s).lower().replace(",", "").replace("$", "").replace(" ", "")


def _tokens(value: Any) -> set[str]:
    out: set[str] = set()
    if value is None:
        return out
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        out.add(_norm(str(value)))
        out.add(_norm(f"{value:g}"))
        return out
    if isinstance(value, (list, tuple)):
        for v in value:
            out |= _tokens(v)
        return out
    if isinstance(value, dict):
        for v in value.values():
            out |= _tokens(v)
        return out
    text = str(value)
    for m in _TOKEN.finditer(text):
        tok = m.group(0).strip(_EDGE)
        if len(tok) >= 3:
            out.add(_norm(tok))
    for m in _MONEY.finditer(text):
        out.add(_norm(m.group(0)))
    out.add(_norm(text))
    return {t for t in out if t}


def _tool_names(tools: list[dict]) -> list[str]:
    names = []
    for t in tools:
        fn = (t.get("function") or {}).get("name")
        if fn:
            names.append(str(fn))
    return names


def _is_critical(tool: str) -> bool:
    return bool(_CRITICAL.search(tool))


def _is_observe(tool: str) -> bool:
    return bool(_OBSERVE.match(tool))


@dataclass
class DriftGate:
    """Stateful DRIFT-shaped monitor for one episode."""

    user_prompt: str
    tools: list[dict]
    plan_tools: set[str] = field(default_factory=set)
    prompt_tokens: set[str] = field(default_factory=set)
    return_tokens: set[str] = field(default_factory=set)

    @classmethod
    def from_scenario(cls, user_prompt: str, tools: list[dict]) -> DriftGate:
        names = _tool_names(tools)
        prompt_l = user_prompt.lower()
        # Secure planner (deterministic): tools whose names appear in the query,
        # plus observe tools needed for open-ended work. Never reads tool output.
        plan: set[str] = set()
        for n in names:
            stem = n.replace("_", " ")
            if n.lower() in prompt_l or any(
                    p and p in prompt_l for p in stem.split() if len(p) > 3):
                plan.add(n)
            if _is_observe(n):
                plan.add(n)
        if not any(_is_critical(n) for n in plan):
            # Query names the work but not the tool id (e.g. "pay each engineer").
            # Privilege the consequential tools present in the catalog.
            plan |= {n for n in names if _is_critical(n)}
        if not plan:
            plan = set(names)
        return cls(
            user_prompt=user_prompt,
            tools=tools,
            plan_tools=plan,
            prompt_tokens=_tokens(user_prompt),
        )

    def record_return(self, tool: str, result: str) -> None:
        # Isolator: returns are tracked for taint checks but never fed to planner.
        self.return_tokens |= _tokens(result)

    def _tainted(self, args: dict) -> bool:
        """True if some arg value appears in tool returns but not in the query."""
        for val in args.values():
            for tok in _tokens(val):
                if tok in self.return_tokens and tok not in self.prompt_tokens:
                    return True
        return False

    def authorize(self, tool: str, args: dict) -> tuple[bool, str]:
        # Injection isolator on consequential calls.
        if _is_critical(tool) and self._tainted(args):
            return False, (
                f"DENIED by DRIFT isolator: '{tool}' args derive from tool "
                f"output not present in the user query")

        if tool in self.plan_tools:
            return True, "allow"

        # Dynamic validator: off-plan deviation.
        if _is_observe(tool) or not _is_critical(tool):
            # Fail-open for discovery tools (utility path in DRIFT).
            self.plan_tools.add(tool)
            return True, "allow-replan-observe"

        # Consequential off-plan: allow only if every arg is prompt-grounded
        # (still consistent with user intent; no observation influence).
        for val in args.values():
            toks = _tokens(val)
            if toks and not any(t in self.prompt_tokens for t in toks):
                return False, (
                    f"DENIED by DRIFT validator: off-plan consequential tool "
                    f"'{tool}' with args not grounded in the user query")
        self.plan_tools.add(tool)
        return True, "allow-replan-grounded"

    def deny_message(self, reason: str) -> str:
        return reason + ". Do not retry the same untrusted action."
