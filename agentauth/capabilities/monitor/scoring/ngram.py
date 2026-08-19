"""Deterministic goal-conditioned n-gram scorer.

A dependency-free surprise model: it learns, per goal bucket, how likely each
action token is given the preceding token(s) in benign trajectories, and scores
a new action by its negative log-probability under that model with add-k
smoothing and backoff. It runs on any machine, needs no training loop, and is
the honest floor the learned transformer must beat. It is also the fallback the
detector uses when torch is unavailable, so the whole pipeline (including the
conformal guarantee) works offline.

Goal conditioning is by *bucket* (a coarse goal signature) rather than the raw
goal text, so counts are shareable across similar tasks and estimable from
realistic trajectory volumes.
"""
from __future__ import annotations

import math
from collections import defaultdict

from agentauth.capabilities.monitor.action import (
    Trajectory,
    action_token,
    goal_tokens,
)
from agentauth.capabilities.monitor.scoring.base import ScoredStep


def goal_bucket(traj: Trajectory) -> str:
    """Coarse goal signature used to condition the counts."""
    tokens = goal_tokens(traj.goal)
    kind = next((t for t in tokens if t.startswith("goal:")), None)
    allow = sorted(t for t in tokens if t.startswith("allow:"))
    return kind or (allow[0] if allow else "g:generic")


class NGramScorer:
    name = "ngram"

    def __init__(self, *, order: int = 2, add_k: float = 0.5) -> None:
        self.order = max(2, order)
        self.add_k = add_k
        # bucket -> context-token -> next-token -> count
        self._bigram: dict[str, dict[str, dict[str, int]]] = defaultdict(
            lambda: defaultdict(lambda: defaultdict(int))
        )
        self._unigram: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._vocab: set[str] = set()
        self._fitted = False

    def fit(self, trajectories: list[Trajectory]) -> NGramScorer:
        for traj in trajectories:
            bucket = goal_bucket(traj)
            prev = "<bos>"
            for action in traj.actions:
                tok = action_token(action)
                self._vocab.add(tok)
                self._bigram[bucket][prev][tok] += 1
                self._unigram[bucket][tok] += 1
                prev = tok
        self._fitted = True
        return self

    def _log_prob(self, bucket: str, prev: str, tok: str) -> float:
        vocab_size = max(1, len(self._vocab))
        ctx = self._bigram.get(bucket, {}).get(prev)
        if ctx:
            total = sum(ctx.values())
            prob = (ctx.get(tok, 0) + self.add_k) / (total + self.add_k * vocab_size)
            return math.log(prob)
        # Backoff to the bucket unigram, then to a uniform prior.
        uni = self._unigram.get(bucket)
        if uni:
            total = sum(uni.values())
            prob = (uni.get(tok, 0) + self.add_k) / (total + self.add_k * vocab_size)
            return math.log(prob)
        return math.log(1.0 / vocab_size)

    def surprise(self, traj: Trajectory) -> list[ScoredStep]:
        if not self._fitted:
            # Unfitted model is maximally uninformed: flat surprise.
            return [ScoredStep(a.step, 0.0) for a in traj.actions]
        bucket = goal_bucket(traj)
        out: list[ScoredStep] = []
        prev = "<bos>"
        for action in traj.actions:
            tok = action_token(action)
            out.append(ScoredStep(action.step, -self._log_prob(bucket, prev, tok)))
            prev = tok
        return out
