from __future__ import annotations

import re

from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.capabilities.scoping.tools.entity_index import ToolEntityIndex
from agentauth.capabilities.scoping.tools.entity_match import (
    EntityMatch,
    resolve_target_entities,
)
from agentauth.capabilities.scoping.tools.models import ToolCapabilityLease
from agentauth.capabilities.scoping.tools.target_closure import (
    TargetClosurePolicy,
    compute_target_closure,
)
from agentauth.core.runtime import SideEffectLevel

_TOKEN_RE = re.compile(r"[A-Za-z]{3,}")

_READ_ONLY_LEVELS = {SideEffectLevel.READ_ONLY}


def _word_tokens(text: str) -> set[str]:
    """Word-level tokens, splitting snake_case/kebab-case tool names into
    their component words ("issue_payroll_bonus" -> {issue, payroll, bonus})
    -- a plain word-boundary regex over an unsplit identifier would treat
    the whole underscore-joined name as one token that can never overlap
    with space-separated goal text. Tokens are kept in their original form
    (no blind stemming -- an earlier version stripped trailing "s"
    indiscriminately and corrupted "bonus" itself into "bonu"); plural/verb
    variants are handled at comparison time instead, see ``_tokens_match``."""
    normalized = text.replace("_", " ").replace("-", " ")
    return set(_TOKEN_RE.findall(normalized.lower()))


def _tokens_match(a: str, b: str) -> bool:
    """Suffix-tolerant equality: "bonus"/"bonuses", "payment"/"payments".
    Deliberately a pairwise comparison, not a canonical-form rewrite of
    each token -- rewriting "bonus" itself on its own (e.g. stripping a
    trailing "s") mangles ordinary words that end in "s" without being
    plural ("bonus", "status", "access")."""
    if a == b:
        return True
    for longer, shorter in ((a, b), (b, a)):
        if longer == shorter + "s" or longer == shorter + "es":
            return True
    return False


def _any_token_overlap(tokens_a: set[str], tokens_b: set[str]) -> bool:
    return any(_tokens_match(a, b) for a in tokens_a for b in tokens_b)


def score_targets_for_goal(
    index: ToolEntityIndex,
    goal: GoalSpec,
    *,
    top_k: int = 10,
) -> list[EntityMatch]:
    return resolve_target_entities(goal.summary, index, top_k=top_k)


def _tool_matches_goal(tool_name: str, description: str, goal_tokens: set[str]) -> bool:
    """Token-overlap tool relevance -- same pattern as capability_scope.py's
    ``_token_match_rank``, adapted to a small enumerable tool list instead of
    a repo-scale chunk corpus."""
    if not goal_tokens:
        return False
    haystack_tokens = _word_tokens(tool_name) | _word_tokens(description)
    return _any_token_overlap(goal_tokens, haystack_tokens)


def build_tool_capability_lease(
    index: ToolEntityIndex,
    goal: GoalSpec,
    *,
    closure_policy: TargetClosurePolicy | None = None,
    top_k: int = 10,
) -> ToolCapabilityLease:
    entity_matches = score_targets_for_goal(index, goal, top_k=top_k)
    seed_entities = {match.entity_id for match in entity_matches}
    # Explicit allow_resources naming a known entity_id directly (not parsed
    # as a file path -- GoalSpec.explicit_allow_files() is file-shaped and
    # not reused here since entity ids have no meaningful repo://file: prefix).
    entities_by_id = index.entities_by_id()
    explicit_entities = {r for r in goal.allow_resources if r in entities_by_id}

    closure = compute_target_closure(
        seed_entities=seed_entities | explicit_entities,
        membership_edges=index.membership_edges,
        policy=closure_policy,
    )

    goal_tokens = _word_tokens(goal.summary) if goal.summary else set()
    # Explicit allow_resources naming a tool by name are always in scope,
    # even without a token match (mirrors CapabilityLease.explicit_allow_resources).
    explicit_tool_names = {
        resource for resource in goal.allow_resources if resource in index.tools_by_name()
    }

    expected_tools: set[str] = set(explicit_tool_names)
    expected_targets: dict[str, set[str]] = {}
    seed_evidence: list[dict[str, object]] = [
        {
            "goal_token": match.matched_on,
            "matched_entity_id": match.entity_id,
            "match_score": match.score,
            "matched_on": match.matched_on,
        }
        for match in entity_matches
    ]

    for tool in index.tools:
        explicit = tool.name in explicit_tool_names
        # Shadow/legacy tools are never auto-matched by text relevance --
        # their descriptions can echo the primary tool's vocabulary by
        # construction (that's the whole substitution risk). Only an
        # explicit allow can put one in scope.
        text_relevant = tool.trust_tier == "primary" and _tool_matches_goal(
            tool.name, tool.description, goal_tokens
        )
        if not (explicit or text_relevant):
            continue
        expected_tools.add(tool.name)
        if tool.side_effect_level in _READ_ONLY_LEVELS:
            continue
        if closure.expanded_entities:
            expected_targets[tool.name] = set(closure.expanded_entities)

    return ToolCapabilityLease(
        query_id=goal.query_id,
        snapshot_id=index.snapshot_id,
        seed_evidence=seed_evidence,
        expected_tools=expected_tools,
        expected_targets=expected_targets,
        explicit_allow_targets={},
        metric_id="tool_entity_token_overlap_v1",
    )
