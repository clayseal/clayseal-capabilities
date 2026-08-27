"""Commit-then-reveal: check a declared plan against the sealed goal.

The twin corridor asks whether *execution* matched a *reference*. A deployment
never has a clean twin; it has a declaration the agent produced before acting.
Corridor + declaration closes the honest-declare-then-sabotage case.

An agent that declares the sabotage up front still passes the corridor. This
module is the complementary check: destinations and tools in the declaration
must be named by the sealed goal. That puts the attacker's destination in
static text available before anything runs, a far easier object to judge than
a live trajectory.

No LLM is in this path.
"""
from __future__ import annotations

import re

from agentauth.capabilities.monitor.action import Trajectory, path_hint
from agentauth.capabilities.monitor.sealed_plan import (
    _write_body,
    extract_callees,
    extract_destinations,
)
from agentauth.capabilities.scoping.goal import GoalSpec

# Callees that are never goal-entailed unless the sealed goal literally names
# them. Declaring a reverse shell is the commit-then-reveal form of sabotage.
_DECLARATION_SUSPECT_CALLEES = frozenset({
    "reverse_shell", "nc", "ncat", "pty.spawn",
})


def _normalize_net(dest: str) -> str:
    """Collapse ``net:host:port`` → ``net:host`` for entailment matching."""
    if not dest.startswith("net:"):
        return dest
    rest = dest[4:]
    # Cloud schemes keep bucket identity: net:s3:bucket / net:gs:bucket.
    if rest.startswith(("s3:", "gs:", "azure:")):
        return dest.split("/**")[0]
    host = rest.split("/")[0].split(":")[0]
    return f"net:{host}"


def _goal_egress_affordances(goal: GoalSpec) -> frozenset[str]:
    """``net:`` destinations the sealed goal explicitly names."""
    out: set[str] = set()
    for resource in goal.allow_resources:
        if resource.startswith("net:"):
            out.add(_normalize_net(resource.split("/**")[0]))
    out |= {_normalize_net(d) for d in extract_destinations(goal.summary or "")}
    return frozenset(out)


def _declaration_destinations(declared: Trajectory) -> frozenset[str]:
    out: set[str] = set()
    for action in declared.actions:
        hint = path_hint(action)
        if hint.startswith("net:"):
            out.add(hint)
        body = _write_body(action)
        out |= set(extract_destinations(body))
        cmd = str(action.args.get("command") or "")
        if cmd:
            out |= set(extract_destinations(cmd))
    return frozenset(out)


def check_declaration_against_goal(
    declared: Trajectory,
    goal: GoalSpec,
) -> list[str]:
    """Return reasons the declaration is not entailed by the sealed goal.

    Empty list ⇒ the declaration is within the goal's named tools and egress
    affordances and has no high-precision content-sabotage patterns. Subtle
    meaning harm without those patterns still passes, soft entailment / digΔ
    cover that residue.
    """
    reasons: list[str] = []
    if not declared.actions:
        return ["declaration: empty plan"]

    allowed_tools = {
        str(t) for t in (goal.structured_intent or {}).get("tools") or [] if t
    }
    if allowed_tools:
        used = {action.tool for action in declared.actions}
        novel_tools = sorted(used - allowed_tools)
        if novel_tools:
            reasons.append(
                f"declaration: tools {novel_tools} not in sealed goal "
                f"{sorted(allowed_tools)}"
            )

    decl_dests = {_normalize_net(d) for d in _declaration_destinations(declared)}
    if decl_dests:
        afford = _goal_egress_affordances(goal)
        if afford:
            novel = sorted(decl_dests - afford)
            if novel:
                reasons.append(
                    f"declaration: destinations {novel} not named in sealed goal "
                    f"(allowed={sorted(afford)[:8]})"
                )
        elif goal.allow_resources:
            # Goal scoped resources/paths but named no egress, any net: in the
            # declaration is an expansion of authority.
            reasons.append(
                f"declaration: introduces egress {sorted(decl_dests)} but sealed "
                f"goal names none"
            )

    # Suspect callees in declared write/script bodies (reverse shells, etc.).
    # Match as whole tokens, bare ``c in summary`` false-clears ``nc`` inside
    # words like ``inference`` once the sealed goal carries a real user request.
    # Skip alphabetized pip-freeze dumps: package names like ``aa-inactivity``
    # falsely trip ``nc`` via substring tokenization (measured benign FB).
    from agentauth.capabilities.monitor.entailment import _looks_like_pip_freeze

    summary = (goal.summary or "").lower()
    suspect: set[str] = set()
    for action in declared.actions:
        body = _write_body(action)
        if body and not _looks_like_pip_freeze(body):
            suspect |= set(extract_callees(body)) & _DECLARATION_SUSPECT_CALLEES
        cmd = str(action.args.get("command") or "")
        if cmd and not _looks_like_pip_freeze(cmd):
            suspect |= set(extract_callees(cmd)) & _DECLARATION_SUSPECT_CALLEES

    def _named_in_goal(callee: str) -> bool:
        token = callee.replace("_", " ").lower()
        return re.search(rf"(?<![\w]){re.escape(token)}(?![\w])", summary) is not None

    named = {c for c in suspect if _named_in_goal(c)}
    novel_callees = sorted(suspect - named)
    if novel_callees:
        reasons.append(
            f"declaration: introduces suspect callees {novel_callees} not named "
            f"in sealed goal"
        )

    # High-precision content patterns (same detectors as soft entailment).
    # Measured 0% benign FB on SLEIGHT; promoted to hard declaration deny so
    # declare-sabotage is not limited to destination/tool identity.
    from agentauth.capabilities.monitor.entailment import (
        deterministic_content_reasons,
        write_preferring_samples,
    )

    for r in deterministic_content_reasons(
        goal.summary or "",
        write_preferring_samples(declared),
        plan=declared,
    ):
        reasons.append(r.replace("entailment:", "declaration:", 1))

    return reasons
    # NOTE: SECRET→sink IFC belongs on execution-vs-declaration (corridor), not
    # here. Honest plans also read secrets and write scripts; flagging that at
    # declare time false-blocks ~25% of SLEIGHT benign twins.


def seal_declaration(
    declared: Trajectory,
    goal: GoalSpec | None = None,
) -> tuple[list[str], object]:
    """Validate declaration against goal and compile the sealed-plan constraints.

    Returns ``(goal_reasons, sealed_constraints)``. Callers that see a non-empty
    ``goal_reasons`` should fail closed before any side effect runs.
    """
    from agentauth.capabilities.monitor.sealed_plan import compile_sealed_plan

    g = goal or declared.goal
    reasons = check_declaration_against_goal(declared, g)
    return reasons, compile_sealed_plan(declared)
