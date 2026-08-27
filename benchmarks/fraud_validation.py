"""Validate the AML peer-deviation sensor on real fraud data.

The AML layer's typologies (structuring, fan-out, velocity) are agent-trajectory
patterns; the fraud datasets are per-transaction and cannot exercise those
directly. What they CAN validate is the sensor's learned component, the
peer-group deviation score (``aml.peer_z_score``), on genuinely fraudulent
data, grounding the AML inspiration in reality. We fit the peer statistics on
legitimate transactions and measure how well the same z-score separates held-out
fraud (ROC-AUC and recall at a 1% false-positive rate).

Scope, stated honestly: this validates the peer-deviation mechanism, not the
sequence typologies (which need account-grouped data such as PaySim/IEEE-CIS,
not present here). It uses the ULB credit-card dataset in the sibling receipts
corpus.
"""
from __future__ import annotations

import csv
import random
from pathlib import Path

from agentauth.capabilities.monitor.aml import peer_z_score


def _default_ulb() -> Path:
    return Path(__file__).resolve().parents[2] / "agentauth-receipts" / "benchmarks" / \
        "corpus" / "ulb_creditcard" / "creditcard.csv"


def load_ulb(path: Path | None = None, *, max_legit: int | None = 20000, seed: int = 0):
    """Return ``(feature_dicts, labels)``. Optionally subsample the legit class."""
    path = Path(path) if path else _default_ulb()
    if not path.exists():
        raise RuntimeError(f"ULB dataset not found at {path}")
    rng = random.Random(seed)
    feats: list[dict[str, float]] = []
    labels: list[int] = []
    with path.open() as handle:
        reader = csv.DictReader(handle)
        cols = [c for c in reader.fieldnames or [] if c not in ("Time", "Class")]
        for row in reader:
            label = int(float(row["Class"]))
            if label == 0 and max_legit is not None and rng.random() > 0.15:
                continue  # cheap subsample of the majority class
            feats.append({c: float(row[c]) for c in cols})
            labels.append(label)
    return feats, labels


def _fit_peer(feats: list[dict[str, float]]) -> tuple[dict[str, float], dict[str, float]]:
    import statistics
    keys = feats[0].keys()
    mean = {k: statistics.fmean(f[k] for f in feats) for k in keys}
    std = {k: (statistics.pstdev(f[k] for f in feats) or 1e-9) for k in keys}
    return mean, std


def roc_auc(scores: list[float], labels: list[int]) -> float:
    # Mann-Whitney: P(score_pos > score_neg), ties counted as 0.5.
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    rank = [0.0] * len(scores)
    i = 0
    while i < len(order):
        j = i
        while j < len(order) and scores[order[j]] == scores[order[i]]:
            j += 1
        avg = (i + j - 1) / 2 + 1  # 1-based average rank
        for k in range(i, j):
            rank[order[k]] = avg
        i = j
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return 0.5
    sum_pos = sum(rank[i] for i in range(len(labels)) if labels[i] == 1)
    return (sum_pos - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)


def recall_at_fpr(scores, labels, fpr: float = 0.01) -> float:
    neg = sorted((scores[i] for i in range(len(labels)) if labels[i] == 0), reverse=True)
    if not neg:
        return 0.0
    threshold = neg[min(int(len(neg) * fpr), len(neg) - 1)]
    caught = sum(1 for i in range(len(labels)) if labels[i] == 1 and scores[i] >= threshold)
    total = sum(labels)
    return caught / total if total else 0.0


def evaluate(path: Path | None = None, *, seed: int = 0) -> dict:
    feats, labels = load_ulb(path, seed=seed)
    idx = list(range(len(feats)))
    random.Random(seed).shuffle(idx)
    split = int(len(idx) * 0.6)
    train = [i for i in idx[:split] if labels[i] == 0]  # peer group = legit only
    test = idx[split:]
    mean, std = _fit_peer([feats[i] for i in train])
    scores = [peer_z_score(feats[i], mean, std)[0] for i in test]
    y = [labels[i] for i in test]
    return {
        "n_test": len(test), "n_fraud": sum(y),
        "auc": round(roc_auc(scores, y), 4),
        "recall_at_1pct_fpr": round(recall_at_fpr(scores, y, 0.01), 4),
    }


def main() -> int:
    import json
    import sys
    try:
        result = evaluate()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("AML peer-deviation on ULB credit-card fraud:")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
