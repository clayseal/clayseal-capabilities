"""Vocabulary, tokenization, and trajectory (de)serialization.

Pure Python so it is testable and usable without torch. The learned scorer and
the training loop share this encoding: a trajectory becomes ``[BOS] + goal
tokens + action tokens``, and only the action positions carry a supervised
next-token target, so the model learns to predict the agent's next action given
the sealed goal and the actions so far.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from clayseal.capabilities.monitor.action import (
    BOS,
    PAD,
    SPECIAL_TOKENS,
    UNK,
    Action,
    ContextItem,
    Trajectory,
    TrustLevel,
    action_token,
    goal_tokens,
)
from clayseal.capabilities.scoping.goal import GoalSpec


# --------------------------------------------------------------------------- #
# Trajectory <-> dict (jsonl corpus format)
# --------------------------------------------------------------------------- #
def trajectory_to_dict(traj: Trajectory) -> dict[str, Any]:
    goal = traj.goal
    return {
        "goal": {
            "query_id": goal.query_id,
            "summary": goal.summary,
            "allow_resources": list(goal.allow_resources),
            "allow_agent_memory_writes": goal.allow_agent_memory_writes,
            "structured_intent": dict(goal.structured_intent),
        },
        "actions": [
            {
                "step": a.step, "tool": a.tool, "resource": a.resource, "verb": a.verb,
                "args": a.args, "derived_from": list(a.derived_from),
                "outcome": a.outcome, "meta": a.meta,
            }
            for a in traj.actions
        ],
        "context": [
            {"item_id": c.item_id, "trust": c.trust.value,
             "introduced_at_step": c.introduced_at_step, "summary": c.summary}
            for c in traj.context
        ],
    }


def trajectory_from_dict(raw: dict[str, Any]) -> Trajectory:
    g = raw.get("goal", {})
    goal = GoalSpec(
        query_id=str(g.get("query_id", "")),
        summary=str(g.get("summary", "")),
        allow_resources=[str(x) for x in g.get("allow_resources", [])],
        allow_agent_memory_writes=bool(g.get("allow_agent_memory_writes", False)),
        structured_intent=dict(g.get("structured_intent", {})),
    )
    actions = [
        Action(
            step=int(a.get("step", i)), tool=str(a.get("tool", "")),
            resource=str(a.get("resource", "")), verb=str(a.get("verb", "call")),
            args=dict(a.get("args", {})), derived_from=tuple(a.get("derived_from", [])),
            outcome=a.get("outcome"), meta=dict(a.get("meta", {})),
        )
        for i, a in enumerate(raw.get("actions", []))
    ]
    context = [
        ContextItem(
            item_id=str(c.get("item_id", "")),
            trust=TrustLevel(c.get("trust", "untrusted")),
            introduced_at_step=int(c.get("introduced_at_step", 0)),
            summary=str(c.get("summary", "")),
        )
        for c in raw.get("context", [])
    ]
    return Trajectory(goal=goal, actions=actions, context=context)


def load_corpus(path: str | Path) -> list[Trajectory]:
    out: list[Trajectory] = []
    with Path(path).open() as handle:
        for line in handle:
            line = line.strip()
            if line:
                out.append(trajectory_from_dict(json.loads(line)))
    return out


def dump_corpus(trajectories: Iterable[Trajectory], path: str | Path) -> None:
    with Path(path).open("w") as handle:
        handle.writelines(json.dumps(trajectory_to_dict(traj)) + "\n" for traj in trajectories)


# --------------------------------------------------------------------------- #
# Vocabulary
# --------------------------------------------------------------------------- #
@dataclass
class Vocab:
    token_to_id: dict[str, int]

    @property
    def id_to_token(self) -> dict[int, str]:
        return {i: t for t, i in self.token_to_id.items()}

    def __len__(self) -> int:
        return len(self.token_to_id)

    @property
    def pad_id(self) -> int:
        return self.token_to_id[PAD]

    @classmethod
    def build(cls, trajectories: list[Trajectory], *, min_count: int = 1) -> Vocab:
        from collections import Counter

        counts: Counter[str] = Counter()
        for traj in trajectories:
            for tok in goal_tokens(traj.goal):
                counts[tok] += 1
            for action in traj.actions:
                counts[action_token(action)] += 1
        tokens = [t for t, c in counts.most_common() if c >= min_count]
        vocab = {tok: i for i, tok in enumerate(SPECIAL_TOKENS)}
        for tok in tokens:
            vocab.setdefault(tok, len(vocab))
        return cls(token_to_id=vocab)

    def encode(self, traj: Trajectory) -> tuple[list[int], list[int]]:
        """Return ``(ids, action_positions)`` for a trajectory.

        ``ids`` is ``[BOS] + goal tokens + action tokens``. ``action_positions``
        indexes the action tokens within ``ids`` so training and scoring read
        surprise only where an action was actually taken.
        """
        unk = self.token_to_id[UNK]
        ids = [self.token_to_id[BOS]]
        for tok in goal_tokens(traj.goal):
            ids.append(self.token_to_id.get(tok, unk))
        action_positions: list[int] = []
        for action in traj.actions:
            action_positions.append(len(ids))
            ids.append(self.token_to_id.get(action_token(action), unk))
        return ids, action_positions

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.token_to_id, indent=0))

    @classmethod
    def load(cls, path: str | Path) -> Vocab:
        return cls(token_to_id=json.loads(Path(path).read_text()))
