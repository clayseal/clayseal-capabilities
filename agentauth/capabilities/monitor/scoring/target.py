"""Target-identity surprise: the channel the token space throws away.

``action_token`` reduces an action to ``verb|tool|resource_class``, and
``resource_class`` collapses every concrete resource to its scheme. That keeps
the sequence vocabulary estimable, which is the right call for an n-gram — and it
destroys the only signal that separates benign from attack on the corpora where
the threat is *where the agent reached*. Measured on this repo's own loaders:

    corpus    distinct action tokens    distinct paths
    redcode                        4               248
    sleight                       10               168

Every one of RedCode's 248 paths is the single symbol ``workspace``. Reading
``app/summary.txt`` and reading ``~/.ssh/id_rsa`` are the same token, so on
SLEIGHT the benign and attack histograms match almost cell for cell and 100% of
attack actions carry a token that also occurs in benign. No scorer recovers that:
the information is gone before any model sees it.

The fix is not a bigger vocabulary — a flat multinomial over hundreds of paths is
not estimable from realistic trajectory counts, which is exactly what the
collapse was avoiding. The fix is to stop asking one channel to carry two
signals. This module is the second channel, and it uses a representation suited
to *identity* rather than to *shape*: resource references are hierarchical, and a
backoff density over that hierarchy is extremely sample-efficient.

## Why a density and not a wildcard

A syntactic grant generalized to ``~/repo/**`` admits ``repo/.git/config`` by the
same rule that admits ``repo/app/summary.txt``. That is the generalization cliff
in one line: the pattern that recovers friction admits the attack. A density does
not have that property. Under ``goal:summarize-app`` the cohort has touched
``app/`` twelve hundred times and ``.git/`` never, so the two paths score
decades apart while sitting inside the identical grant.

This is the move human UEBA makes and this system did not: Peter has access to
the finance share (the ACL), *and* has never opened these four hundred files
(the baseline). The grant stays wide enough for a human to write; the density
does the discriminating inside it.

## The estimator

Absolute discounting down the resource trie, backing off to a segment marginal:

    P(seg | node) = max(count(seg) - d, 0) / N(node)          observed child
                  + (d * U(node) / N(node)) * P_marginal(seg)  escape mass

``U`` is the node's distinct-child count, so the escape mass is small exactly
where the cohort is concentrated. That is the property doing the work: a node
seen 1,204 times with three children reserves almost no mass for a fourth, so a
novel branch there is very surprising, while a node seen five times with five
children reserves a lot and a novel branch is barely remarkable. The model is
appropriately unsure where it has seen little, which is what keeps this from
becoming a false-positive generator on sparse buckets.

Conditioning is ``(goal_bucket, verb)`` — reading ``/etc`` and writing ``/etc``
are different events — with backoff to ``(goal_bucket)`` and then to a global
trie when a key has too few observations to estimate from. That backoff chain is
the cohort structure in miniature: entity, then peer group, then prior.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from agentauth.capabilities.monitor.action import Action, Trajectory
from agentauth.capabilities.monitor.scoring.base import ScoredStep

_SEGMENT_SPLIT = re.compile(r"[/:\\]+")

# Segments that carry no identity: they are structural noise in every corpus and
# including them dilutes the concentration the escape mass is measuring.
_NOISE_SEGMENTS = frozenset({"", ".", "file", "http", "https", "mcp"})


def action_target(action: Action) -> str:
    """The concrete thing an action reached for.

    ``meta['path']`` where a loader recorded one (RedCode, SLEIGHT: the resource
    field is a constant there and the path is the whole signal), else the
    resource ref (tau2, ATIF: the resource *is* the identity). Falls back to the
    tool name so an action always has some target rather than dropping out of the
    density silently.
    """
    path = (action.meta or {}).get("path")
    if path:
        return str(path)
    return action.resource or action.tool or ""


def segments(target: str) -> tuple[str, ...]:
    """Split a resource ref or path into hierarchy segments, coarsest first.

    Parent traversals are kept as literal ``..`` segments rather than normalized
    away: an agent reaching upward out of its workspace is precisely the event
    this channel exists to notice, and resolving the path first would erase it.
    """
    parts = [p for p in _SEGMENT_SPLIT.split(target.strip())
             if p and p.lower() not in _NOISE_SEGMENTS]
    return tuple(parts)


@dataclass
class _Node:
    total: int = 0
    children: dict[str, _Node] = field(default_factory=dict)

    @property
    def distinct(self) -> int:
        return len(self.children)


@dataclass
class _Trie:
    root: _Node = field(default_factory=_Node)
    observations: int = 0

    def add(self, path: tuple[str, ...]) -> None:
        node = self.root
        node.total += 1
        for seg in path:
            child = node.children.get(seg)
            if child is None:
                child = node.children[seg] = _Node()
            child.total += 1
            node = child
        self.observations += 1


class TargetDensityScorer:
    """Goal-conditioned surprise over *which* resource an action reached for.

    Implements the ``SequenceScorer`` protocol, so it drops in anywhere the
    n-gram scorer goes and composes with the existing conformal layer unchanged.
    It is deliberately independent of the sequence channel: the two disagree
    often, and that is the point of factorizing them.
    """

    name = "target"

    def __init__(self, *, discount: float = 0.5, min_observations: int = 12,
                 reduce: str = "max") -> None:
        if reduce not in ("max", "mean"):
            raise ValueError("reduce must be 'max' or 'mean'")
        self.discount = discount
        self.min_observations = min_observations
        # 'max' is the default because the discriminative event is a single
        # branch off the known tree, and a max is invariant to path depth. A sum
        # would rank every deep path above every shallow one regardless of where
        # it went, which is a length artifact rather than a signal.
        self.reduce = reduce
        self._tries: dict[str, _Trie] = {}
        self._buckets_seen: set[str] = set()
        self._segment_counts: dict[str, int] = {}
        self._segment_total = 0
        self._fitted = False

    # ----------------------------------------------------------------- fit --
    def fit(self, trajectories: list[Trajectory]) -> TargetDensityScorer:
        from agentauth.capabilities.monitor.scoring.ngram import goal_bucket

        for traj in trajectories:
            bucket = goal_bucket(traj)
            self._buckets_seen.add(bucket)
            for action in traj.actions:
                path = segments(action_target(action))
                if not path:
                    continue
                for key in self._keys(bucket, action.verb):
                    self._tries.setdefault(key, _Trie()).add(path)
                for seg in path:
                    self._segment_counts[seg] = self._segment_counts.get(seg, 0) + 1
                    self._segment_total += 1
        self._fitted = True
        return self

    @staticmethod
    def _keys(bucket: str, verb: str) -> tuple[str, str, str]:
        """Conditioning keys, most specific first: entity, peer group, prior."""
        return (f"{bucket}|{verb}", bucket, "*")

    # --------------------------------------------------------------- score --
    def _trie_for(self, bucket: str, verb: str) -> _Trie | None:
        """Most specific trie with enough observations to estimate from.

        The backoff chain is entity -> peer group -> prior, but it is **gated on
        the goal bucket existing at all**. A bucket never seen in training has no
        peer group and no entity history, and falling through to the global prior
        would score its first entirely legitimate action at double-digit bits —
        a new customer agent would light up as an incident on the day it shipped.

        That gate matters more than it looks. The conformal layer downstream
        cannot calibrate a bucket it has no benign samples for, so a block issued
        here would be an *uncalibrated* block: exactly the defect where a
        structural tier blocks outright while the alpha dial does nothing. Cold
        start degrades to the per-action floor, which is the safe direction.
        """
        if bucket not in self._buckets_seen:
            return None
        for key in self._keys(bucket, verb):
            trie = self._tries.get(key)
            if trie is not None and trie.observations >= self.min_observations:
                return trie
        return None

    def _escape(self, node: _Node) -> float:
        """Mass reserved for a child this node has never seen.

        ``d*U/N`` alone is wrong at a **terminal** node. A path that always ended
        here has ``U=0``, so the discounted term is exactly zero and any deeper
        continuation scores ``-log2(1e-12)`` = 39.9 bits — maximally surprising,
        blocked outright. That is a false-positive generator: an agent legitimately
        touching ``app/documents/new.txt`` when the baseline only ever saw
        ``app/documents`` would be refused, and the corpora here did not catch it
        only because their benign paths happen to be uniformly shallow.

        The floor is the add-one estimate of novelty: after ``N`` observations at
        a node with no branching seen, the next one is novel with probability
        about ``1/(N+1)``. So a node visited four times admits a new child at
        ~2.3 bits rather than 39.9, and a node visited a thousand times still
        treats one as genuinely surprising. Found by ``concentration()``, which
        is the argument for shipping that diagnostic alongside the estimator.
        """
        if node.total <= 0:
            return 1.0
        return max(self.discount * node.distinct / node.total,
                   1.0 / (node.total + 1))

    def _marginal(self, seg: str) -> float:
        """Segment marginal with add-one mass for a never-seen segment."""
        if not self._segment_total:
            return 1e-6
        vocab = len(self._segment_counts) + 1
        return (self._segment_counts.get(seg, 0) + 1) / (self._segment_total + vocab)

    def segment_surprises(self, bucket: str, action: Action) -> list[float]:
        """Bits of surprise contributed by each segment of the action's target."""
        path = segments(action_target(action))
        if not path or not self._fitted:
            return []
        trie = self._trie_for(bucket, action.verb)
        if trie is None:
            return []  # abstain: no evidence is not evidence of anomaly
        # Contribute surprise only where the baseline is actually estimated.
        # Past ``ready_depth`` the escape mass is dominated by an unseen-target
        # namespace rather than by anything the cohort's behaviour implies, and
        # the bits it produces there are noise a threshold has to absorb.
        limit = self.ready_depth(bucket, action.verb)
        if limit < 0:
            return []

        out: list[float] = []
        node: _Node | None = trie.root
        for depth, seg in enumerate(path):
            if depth > limit:
                break
            if node is None or node.total <= 0:
                # Already off the known tree: remaining segments cost their
                # marginal only. Stacking escape penalties past the branch point
                # would score a long unknown path as many times more anomalous
                # than the single wrong turn that produced it.
                out.append(-math.log2(self._marginal(seg)))
                continue
            child = node.children.get(seg)
            escape = self._escape(node)
            if child is not None:
                p = max(child.total - self.discount, 0.0) / node.total
                p += escape * self._marginal(seg)
            else:
                p = escape * self._marginal(seg)
            out.append(-math.log2(max(p, 1e-12)))
            node = child
        return out

    def surprise(self, traj: Trajectory) -> list[ScoredStep]:
        from agentauth.capabilities.monitor.scoring.ngram import goal_bucket

        bucket = goal_bucket(traj)
        steps: list[ScoredStep] = []
        for action in traj.actions:
            bits = self.segment_surprises(bucket, action)
            if not bits:
                value = 0.0
            elif self.reduce == "max":
                value = max(bits)
            else:
                value = sum(bits) / len(bits)
            steps.append(ScoredStep(step=action.step, surprise=value))
        return steps

    #: Observations per distinct target below which the channel cannot separate.
    #: Measured, not chosen. ``benchmarks/concentration.py --curve`` subsamples
    #: three corpora and finds depth-1 novel-child surprise tracking a single
    #: governing variable — observations per distinct target — regardless of
    #: whether the corpus is synthetic or real, tool-catalog or filesystem:
    #:
    #:     obs/target   1.7   3.0   4.5   8.3   75    196
    #:     novel bits   1.8   2.6   3.2   4.1   5.1   6.1
    #:
    #: Below ~5 the escape mass is so large that a novel target earns under 3
    #: bits, the conformal gate never fires, and the rung is inert while still
    #: reporting a fitted scorer and a plausible threshold. That failure is
    #: silent, which is why readiness is computed rather than assumed.
    READY_OBS_PER_TARGET = 5.0

    def ready_depth(self, bucket: str, verb: str = "") -> int:
        """Deepest trie level this baseline has enough evidence to judge.

        Readiness is not one bit, it is a **depth**, and conflating the two was
        the last silent failure in this channel. On RedCode the root is estimated
        from 123 observations over 2 children — escape 0.003, a genuinely sharp
        boundary — while depth 1 has 68 distinct targets over the same traffic,
        1.8 per target, which cannot separate anything. A single global readiness
        flag either throws the root away or claims the leaves.

        The adaptive ladder is that asymmetry measured from the other side: the
        channel catches L0 (a novel *root*) at 66.6% and L1/L2 (a novel *leaf*)
        at exactly 0. Returning a depth makes the limit structural — the scorer
        stops contributing surprise where it stops knowing anything, instead of
        contributing noise that a threshold has to absorb.

        Returns -1 when even the root is unsupported.
        """
        trie = self._trie_for(bucket, verb)
        if trie is None:
            return -1
        depth, frontier, ready = 0, [trie.root], -1
        while frontier and depth <= 16:
            observations = sum(n.total for n in frontier)
            children = sum(n.distinct for n in frontier)
            if children == 0:
                break
            if observations / children < self.READY_OBS_PER_TARGET:
                break
            ready = depth
            frontier = [c for n in frontier for c in n.children.values()]
            depth += 1
        return ready

    def readiness(self, bucket: str | None = None) -> dict:
        """Can this baseline support a decision yet, and if not, what is missing?

        The channel's power is not a fixed property of the mechanism — it is a
        function of how much clean traffic the cohort has accumulated, and it
        grows monotonically with it. So "does the density work?" is the wrong
        question; the answerable one is "how much traffic until it does?", and
        this returns the current position on that curve.

        Reported per goal bucket because readiness is not global. In a real
        deployment a tenant's established workflows will clear the bar while a
        newly shipped agent type sits far below it, and a single corpus-wide
        switch would either block on the new one or abstain on the mature ones.
        """
        keys = ([bucket] if bucket is not None
                else sorted(self._buckets_seen))
        out = {}
        for key in keys:
            trie = self._tries.get(key)
            if trie is None:
                out[key] = {"ready": False, "reason": "no baseline",
                            "observations": 0, "obs_per_target": 0.0}
                continue
            distinct = len(trie.root.children) or 1
            leaves = self._distinct_paths(trie.root)
            per_target = trie.observations / max(leaves, 1)
            ready = per_target >= self.READY_OBS_PER_TARGET
            out[key] = {
                "ready": ready,
                "observations": trie.observations,
                "distinct_targets": leaves,
                "distinct_roots": distinct,
                "obs_per_target": per_target,
                "reason": "" if ready else (
                    f"{per_target:.1f} observations per distinct target; needs "
                    f"{self.READY_OBS_PER_TARGET:.0f}. About "
                    f"{int(self.READY_OBS_PER_TARGET * leaves) - trie.observations} "
                    f"more clean actions at the current namespace size."),
            }
        return out if bucket is None else out[bucket]

    @staticmethod
    def _distinct_paths(node: _Node) -> int:
        """Leaf count — the size of the target namespace this trie has seen."""
        if not node.children:
            return 1
        return sum(TargetDensityScorer._distinct_paths(c)
                   for c in node.children.values())

    def concentration(self, max_depth: int = 3) -> list[dict]:
        """Per-depth escape mass: how much protection this baseline can give.

        **Read this before deploying the channel, not after.** The discriminative
        power at a node is governed entirely by its escape mass ``d*U/N``, and
        that is computable from clean traffic alone — no attacks, no labels. A
        node with many distinct children relative to its observation count
        reserves most of its mass for novel children, so a novel child there is
        *not surprising* and the channel cannot see an attacker who relocates to
        it.

        The measurement that motivated this method: on RedCode the root node has
        N=53, U=2, escape 0.019 — highly concentrated, so a target outside the
        workspace is very surprising. One level down, ``app`` has N=41, U=26,
        escape 0.317. Benign traffic there is nearly all-distinct (99 distinct
        paths over 314 events), so the baseline has learned exactly **one bit**:
        the workspace root. An adversary who keeps its target under a known root
        pays essentially nothing, which is what
        ``benchmarks/density_adaptive.py`` measured: density-attributed
        containment falls 66.6% -> 6.1% -> 0.0% across the mimicry ladder.

        So this is the honest precondition. The channel is worth deploying where
        cohort traffic concentrates and is worth very little where it does not,
        and which case a tenant is in is knowable in advance.
        """
        rows: list[dict] = []
        for key, trie in sorted(self._tries.items()):
            frontier = [(trie.root, 0, "<root>")]
            while frontier:
                node, depth, label = frontier.pop(0)
                if depth > max_depth or node.total <= 0:
                    continue
                escape = self._escape(node)
                rows.append({
                    "key": key, "depth": depth, "node": label,
                    "n": node.total, "distinct": node.distinct,
                    "escape": escape,
                    # Bits of surprise a novel child at this node would earn from
                    # the escape term alone, before the segment marginal. Below
                    # ~2 bits the node cannot separate anything.
                    "novel_child_bits": -math.log2(max(escape, 1e-12)),
                })
                for seg, child in sorted(node.children.items(),
                                         key=lambda kv: -kv[1].total)[:8]:
                    frontier.append((child, depth + 1, f"{label}/{seg}"))
        return rows

    def explain(self, traj: Trajectory, action: Action) -> str:
        """Analyst-facing reason. A UEBA alert nobody can read is shelfware."""
        from agentauth.capabilities.monitor.scoring.ngram import goal_bucket

        path = segments(action_target(action))
        bits = self.segment_surprises(goal_bucket(traj), action)
        if not bits:
            return "no target baseline for this goal bucket (abstained)"
        worst = max(range(len(bits)), key=lambda i: bits[i])
        prefix = "/".join(path[:worst]) or "<root>"
        return (f"segment {path[worst]!r} under {prefix} is {bits[worst]:.1f} bits "
                f"for verb {action.verb!r}: the cohort has not reached there "
                f"under this goal")
