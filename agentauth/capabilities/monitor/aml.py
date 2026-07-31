"""AML-style analytics over the action stream.

Anti-money-laundering does not read the memo field of a wire; it scores the
*shape* of activity: velocity, fan-out, structuring (many just-under-threshold
transfers), and deviation from a peer group. The memo asks for the same posture
over agent actions ("more like fraud detection or AML than a normal sandbox").
Each detector here is a pure function of action metadata — verbs, amounts,
targets, counts, order — so it is injection-resistant: an attacker can cause a
suspicious pattern but cannot write text that explains it away.

Typologies are interpretable hard signals; peer-group deviation is a learned
structural distance from the benign population for the goal. Both compose with
the Waymo path envelope and the learned scorer.
"""
from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass, field

from agentauth.capabilities.monitor.action import Trajectory
from agentauth.capabilities.monitor.scoring.ngram import goal_bucket

_EGRESS_VERBS = {"send", "transfer", "post", "share"}
_VALUE_VERBS = {"transfer", "pay", "send"}
_DESTRUCTIVE_VERBS = {"delete", "remove", "drop", "revoke", "wipe"}
_ROUND_THRESHOLDS = (100.0, 500.0, 1000.0, 5000.0, 10000.0, 50000.0)

# Security-relevant surfaces for delegated-trust laundering. A cross-boundary
# summary (main/sidekick) that steers an action touching one of these is the
# Devin/Fusion threat: trust laundered across an unauthenticated boundary into a
# change of the authorization surface.
_SECURITY_SURFACE = ("auth", "permission", "role", "acl", "iam", "credential",
                     "security", "policy", "token", "secret", "grant", "privilege",
                     "sudo", "admin", "firewall", "access")


def _touches_security_surface(action) -> bool:
    hay = " ".join([action.tool, action.resource,
                    " ".join(str(v) for v in action.args.values())]).lower()
    return any(term in hay for term in _SECURITY_SURFACE)


def peer_z_score(feats: dict[str, float], mean: dict[str, float],
                 std: dict[str, float]) -> tuple[float, str]:
    """Peer-group deviation: the largest positive z-score across features, and
    which feature. This is the AML sensor's learned anomaly signal; shared so it
    can be validated directly on real fraud data (see benchmarks/fraud_validation)."""
    worst_z, worst_k = 0.0, ""
    for k, x in feats.items():
        s = std.get(k) or 1e-9
        z = (x - mean.get(k, 0.0)) / s
        if z > worst_z:
            worst_z, worst_k = z, k
    return worst_z, worst_k


@dataclass
class AmlVerdict:
    typologies: tuple[str, ...]
    peer_z: float
    reasons: tuple[str, ...]

    @property
    def flagged(self) -> bool:
        return bool(self.typologies)


def _features(traj: Trajectory) -> dict[str, float]:
    verb_counts: dict[str, int] = defaultdict(int)
    tool_counts: dict[str, int] = defaultdict(int)
    targets: set[str] = set()
    amounts: list[float] = []
    for a in traj.actions:
        verb_counts[a.verb] += 1
        tool_counts[a.tool] += 1
        tgt = a.args.get("target") or a.args.get("to") or a.args.get("recipient")
        if isinstance(tgt, str):
            targets.add(tgt)
        amt = a.args.get("amount")
        if isinstance(amt, (int, float)):
            amounts.append(float(amt))
    return {
        "length": float(len(traj.actions)),
        "n_egress": float(sum(verb_counts[v] for v in _EGRESS_VERBS)),
        "n_value": float(sum(verb_counts[v] for v in _VALUE_VERBS)),
        "distinct_targets": float(len(targets)),
        "max_repetition": float(max(tool_counts.values(), default=0)),
        "total_amount": float(sum(amounts)),
        "max_amount": float(max(amounts, default=0.0)),
    }


@dataclass
class AmlAnalytics:
    peer_z_threshold: float = 4.0
    fanout_floor: int = 5
    structuring_floor: int = 4
    min_samples: int = 25      # peer-group deviation needs a real population
    _mean: dict[str, dict[str, float]] = field(default_factory=dict)
    _std: dict[str, dict[str, float]] = field(default_factory=dict)
    _counts: dict[str, int] = field(default_factory=dict)
    _fitted: bool = False

    def fit(self, benign: list[Trajectory]) -> "AmlAnalytics":
        by_bucket: dict[str, list[dict[str, float]]] = defaultdict(list)
        for traj in benign:
            by_bucket[goal_bucket(traj)].append(_features(traj))
        for bucket, rows in by_bucket.items():
            self._counts[bucket] = len(rows)
            keys = rows[0].keys()
            self._mean[bucket] = {k: statistics.fmean(r[k] for r in rows) for k in keys}
            self._std[bucket] = {
                k: (statistics.pstdev(r[k] for r in rows) or 1e-9) for k in keys
            }
        self._fitted = True
        return self

    def _peer_z(self, bucket: str, feats: dict[str, float]) -> tuple[float, str]:
        mean = self._mean.get(bucket)
        std = self._std.get(bucket)
        if not mean:
            return 0.0, ""
        return peer_z_score(feats, mean, std)

    def assess(self, traj: Trajectory) -> AmlVerdict:
        feats = _features(traj)
        typ: list[str] = []
        reasons: list[str] = []

        # Fan-out: one egress/value action sprayed across many distinct targets.
        if feats["n_egress"] and feats["distinct_targets"] >= self.fanout_floor:
            typ.append("fan-out")
            reasons.append(f"egress to {int(feats['distinct_targets'])} distinct targets")

        # Structuring: several value actions each just below a round threshold.
        just_under = 0
        for a in traj.actions:
            amt = a.args.get("amount")
            if isinstance(amt, (int, float)):
                if any(0.9 * t <= amt < t for t in _ROUND_THRESHOLDS):
                    just_under += 1
        if just_under >= self.structuring_floor:
            typ.append("structuring")
            reasons.append(f"{just_under} value actions just below a round threshold")

        # Escalation: a destructive verb after a run of reads (not the opener).
        verbs = [a.verb for a in traj.actions]
        for i, v in enumerate(verbs):
            if v in _DESTRUCTIVE_VERBS and i > 0 and verbs[:i].count("read") >= 2:
                typ.append("post-read-escalation")
                reasons.append(f"destructive {v!r} after reads")
                break

        # Delegated-trust laundering: an action that touches the security surface
        # and is justified by untrusted, post-seal cross-boundary context (a
        # sidekick summary). Structural — provenance labels plus target surface,
        # no content read. This is the Devin/Fusion main/sidekick threat.
        untrusted = {
            c.item_id for c in traj.context
            if getattr(c.trust, "value", c.trust) == "untrusted"
        }
        for a in traj.actions:
            if a.verb != "read" and untrusted.intersection(a.derived_from) and _touches_security_surface(a):
                typ.append("delegated-trust-laundering")
                reasons.append(
                    f"{a.verb} on security surface justified by untrusted "
                    f"cross-boundary context {sorted(untrusted.intersection(a.derived_from))}"
                )
                break

        # Peer-group deviation: structural distance from the benign population.
        # Needs a real population; abstain on an undertrained bucket.
        peer_z = 0.0
        bucket = goal_bucket(traj)
        if self._fitted and self._counts.get(bucket, 0) >= self.min_samples:
            peer_z, worst = self._peer_z(bucket, feats)
            if peer_z >= self.peer_z_threshold:
                typ.append("peer-deviation")
                reasons.append(f"{worst} is {peer_z:.1f}sigma above peer group")

        seen: set[str] = set()
        return AmlVerdict(
            typologies=tuple(t for t in typ if not (t in seen or seen.add(t))),
            peer_z=peer_z,
            reasons=tuple(reasons),
        )
