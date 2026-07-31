"""Action-stream model for goal-conditional trajectory security.

The behavioral layer reasons over a *trajectory*: the sealed goal plus the
ordered stream of actions the agent attempted. Every per-action authorization
decision (commit token, scope, budget) has already run; this layer asks a
different question, namely whether the *sequence* stays faithful to the sealed
intent even when each step is individually permitted.

Two representational commitments make that tractable:

- A stable ``action_token`` that abstracts a call to ``verb|tool|resource_class``.
  The detector models sequences of these tokens conditioned on the goal, so the
  vocabulary is small and shared between the deterministic scorer, the learned
  transformer scorer, and the structural envelope.
- Explicit provenance: each action records which context items influenced it, so
  taint from untrusted channels (tool output, retrieved documents, memory) can
  be propagated into the decision rather than inferred after the fact.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agentauth.capabilities.scoping.goal import GoalSpec


class TrustLevel(str, Enum):
    """Provenance trust of a context item feeding the agent's reasoning."""

    TRUSTED = "trusted"      # sealed goal, direct user instruction, control plane
    UNTRUSTED = "untrusted"  # tool output, retrieved doc, agent memory, web content


@dataclass(frozen=True)
class ContextItem:
    """A piece of context that can influence an action, with its trust level."""

    item_id: str
    trust: TrustLevel
    introduced_at_step: int = 0
    summary: str = ""


@dataclass(frozen=True)
class Action:
    """One attempted agent action in a trajectory.

    ``derived_from`` lists the ``ContextItem`` ids that justified the action, the
    hook the taint tracker uses to decide whether an action is driven by content
    that entered after the goal was sealed.
    """

    step: int
    tool: str
    resource: str
    verb: str
    args: dict[str, Any] = field(default_factory=dict)
    derived_from: tuple[str, ...] = ()
    outcome: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class Trajectory:
    """A sealed goal plus the ordered actions attempted under it."""

    goal: GoalSpec
    actions: list[Action] = field(default_factory=list)
    context: list[ContextItem] = field(default_factory=list)

    def prefix(self, upto: int) -> "Trajectory":
        """Trajectory truncated to the first ``upto`` actions (online scoring)."""
        return Trajectory(goal=self.goal, actions=self.actions[:upto], context=self.context)


# --------------------------------------------------------------------------- #
# Tokenization — the shared symbol space for every scorer and the envelope.
# --------------------------------------------------------------------------- #
_RESOURCE_SPLIT = (":", "/", ".")

# Sentinels shared with the learned scorer's vocabulary.
PAD = "<pad>"
BOS = "<bos>"
EOS = "<eos>"
UNK = "<unk>"
SPECIAL_TOKENS = (PAD, BOS, EOS, UNK)


def resource_class(resource: str) -> str:
    """Collapse a concrete resource ref to a coarse class for the token space.

    ``mcp:tool:send_money`` -> ``mcp:tool``; ``repo://a/b/c.py`` -> ``repo``;
    ``file:secrets/x`` -> ``file``. Keeping the class (not the instance) small
    keeps the sequence vocabulary learnable from realistic trajectory counts.
    """
    if not resource:
        return "none"
    for scheme in ("mcp:tool:", "repo_write://", "repo_read://", "repo://", "file:", "net:"):
        if resource.startswith(scheme):
            head = scheme.rstrip(":/")
            return "mcp:tool" if head.startswith("mcp:tool") else head.split(":", 1)[0].split("/", 1)[0]
    for sep in _RESOURCE_SPLIT:
        if sep in resource:
            return resource.split(sep, 1)[0]
    return resource


def action_token(action: Action) -> str:
    """Canonical ``verb|tool|resource_class`` symbol for an action."""
    return f"{action.verb}|{action.tool}|{resource_class(action.resource)}"


def goal_tokens(goal: GoalSpec) -> list[str]:
    """Content tokens describing the sealed goal, used to condition scoring."""
    tokens: list[str] = []
    intent = goal.structured_intent or {}
    kind = intent.get("kind") or intent.get("type")
    if kind:
        tokens.append(f"goal:{kind}")
    for resource in goal.allow_resources:
        tokens.append(f"allow:{resource_class(resource)}")
    for word in _summary_words(goal.summary):
        tokens.append(f"g:{word}")
    return tokens or ["g:unknown"]


def _summary_words(summary: str, *, limit: int = 16) -> list[str]:
    import re

    words = re.findall(r"[a-z][a-z0-9_]{2,}", (summary or "").lower())
    seen: set[str] = set()
    out: list[str] = []
    for word in words:
        if word not in seen:
            seen.add(word)
            out.append(word)
        if len(out) >= limit:
            break
    return out


def trajectory_tokens(traj: Trajectory) -> list[str]:
    """Full conditioned token sequence: goal context then action tokens."""
    return goal_tokens(traj.goal) + [action_token(a) for a in traj.actions]
