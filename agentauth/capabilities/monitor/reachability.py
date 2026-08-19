"""Waymo-style safe-envelope: does the trajectory stay inside the plausible set
of action paths for its goal?

A self-driving stack asks whether a trajectory stays inside a drivable corridor.
The agent analogue: from benign trajectories of the same goal, learn the corridor
of plausible action paths — which action can follow which, how many times an
action plausibly repeats, how long a path plausibly runs — and flag a trace that
leaves it. This catches the in-scope shapes a per-action check cannot: a scanning
burst (repetition past the corridor), an escalation (a transition never seen in
benign), a fan-out or structuring run (count past the ceiling).

Every feature is structural (action tokens, transitions, counts, length). The
envelope never inspects natural-language content, so an injection can move the
agent but cannot argue its trajectory back inside the corridor.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field

from agentauth.capabilities.monitor.action import Trajectory, action_token
from agentauth.capabilities.monitor.scoring.ngram import goal_bucket


@dataclass
class _BucketEnvelope:
    transitions: set[tuple[str, str]] = field(default_factory=set)
    max_count: dict[str, int] = field(default_factory=dict)
    known_tokens: set[str] = field(default_factory=set)
    length_max: int = 0


@dataclass
class EnvelopeDeparture:
    out_of_envelope: bool
    penalty: float
    reasons: tuple[str, ...]


@dataclass
class PathEnvelope:
    """Per-goal corridor of plausible action paths, learned from benign traces."""

    count_slack: float = 1.5   # allow this multiple of the benign repetition max
    length_slack: float = 1.5
    min_samples: int = 25      # abstain on a bucket calibrated from too few paths
    token_fn: Callable = action_token
    _buckets: dict[str, _BucketEnvelope] = field(default_factory=dict)
    _counts: dict[str, int] = field(default_factory=dict)
    _fitted: bool = False

    def fit(self, benign: list[Trajectory]) -> PathEnvelope:
        by_bucket: dict[str, list[Trajectory]] = defaultdict(list)
        for traj in benign:
            by_bucket[goal_bucket(traj)].append(traj)
        for bucket, trajs in by_bucket.items():
            self._counts[bucket] = len(trajs)
            env = _BucketEnvelope()
            for traj in trajs:
                tokens = [self.token_fn(a) for a in traj.actions]
                env.length_max = max(env.length_max, len(tokens))
                counts: dict[str, int] = defaultdict(int)
                prev = "<bos>"
                for tok in tokens:
                    env.known_tokens.add(tok)
                    env.transitions.add((prev, tok))
                    counts[tok] += 1
                    prev = tok
                for tok, c in counts.items():
                    env.max_count[tok] = max(env.max_count.get(tok, 0), c)
            self._buckets[bucket] = env
        self._fitted = True
        return self

    def assess(self, traj: Trajectory) -> EnvelopeDeparture:
        if not self._fitted:
            return EnvelopeDeparture(False, 0.0, ())
        bucket = goal_bucket(traj)
        env = self._buckets.get(bucket)
        if env is None or self._counts.get(bucket, 0) < self.min_samples:
            # Unknown goal, or too few benign paths to define a corridor: abstain
            # rather than over-flag on an undertrained envelope.
            return EnvelopeDeparture(False, 0.0, ())

        reasons: list[str] = []
        penalty = 0.0
        tokens = [self.token_fn(a) for a in traj.actions]

        if len(tokens) > env.length_max * self.length_slack:
            penalty += len(tokens) - env.length_max
            reasons.append(f"path length {len(tokens)} exceeds corridor ({env.length_max})")

        counts: dict[str, int] = defaultdict(int)
        prev = "<bos>"
        for tok in tokens:
            if tok not in env.known_tokens:
                penalty += 3.0
                reasons.append(f"novel action {tok!r} for goal")
            elif (prev, tok) not in env.transitions:
                penalty += 1.0
                reasons.append(f"novel transition {prev!r}->{tok!r}")
            counts[tok] += 1
            prev = tok

        for tok, c in counts.items():
            ceiling = env.max_count.get(tok, 0) * self.count_slack
            if ceiling and c > ceiling:
                penalty += c - ceiling
                reasons.append(f"repetition of {tok!r} x{c} past corridor ({env.max_count[tok]})")

        # Dedup reasons while preserving order.
        seen: set[str] = set()
        deduped = tuple(r for r in reasons if not (r in seen or seen.add(r)))
        return EnvelopeDeparture(out_of_envelope=penalty > 0, penalty=penalty, reasons=deduped)
