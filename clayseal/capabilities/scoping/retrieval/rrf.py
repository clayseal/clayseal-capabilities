"""Combining rankings without inventing a weight between them.

Reciprocal-rank fusion scores a chunk by its POSITION in each ranking rather than
by each ranking's score. That is the point: a BM25 score and a cosine similarity
are not on the same scale, and any weighted sum of them encodes a tuning constant
nobody measured. Ranks are comparable; scores are not.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass


@dataclass(frozen=True)
class RankedCandidate:
    chunk_id: str
    score: float
    source: str


def reciprocal_rank_fusion(
    ranked_lists: list[list[str]],
    *,
    k: int = 20,
    sources: list[str] | None = None,
) -> list[RankedCandidate]:
    """Fuse multiple ranked chunk-id lists (lower rank index = better)."""
    fused: dict[str, float] = defaultdict(float)
    provenance: dict[str, str] = {}
    for list_idx, ranked in enumerate(ranked_lists):
        source = (sources[list_idx] if sources and list_idx < len(sources) else f"list_{list_idx}")
        for rank, chunk_id in enumerate(ranked):
            fused[chunk_id] += 1.0 / (k + rank + 1)
            provenance.setdefault(chunk_id, source)
    ordered = sorted(fused.items(), key=lambda item: item[1], reverse=True)
    return [
        RankedCandidate(chunk_id=chunk_id, score=score, source=provenance[chunk_id])
        for chunk_id, score in ordered
    ]
