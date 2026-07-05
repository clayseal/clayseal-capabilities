from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from agentauth.capabilities.scoping.models import RepoChunk, SensitivityLabel


@dataclass(frozen=True)
class RerankFeatures:
    chunk: RepoChunk
    bm25_score: float = 0.0
    ann_score: float = 0.0
    rrf_score: float = 0.0
    goal_token_overlap: float = 0.0


@dataclass(frozen=True)
class RerankResult:
    chunk_id: str
    score: float
    reasons: list[str]


class PartnerReranker(Protocol):
    metric_id: str

    def rerank(self, goal_text: str, candidates: list[RerankFeatures]) -> list[RerankResult]: ...


class DefaultChunkReranker:
    """Deterministic v1 reranker until partner metric lands (DP-14 stub)."""

    metric_id = "default-v1"

    def __init__(
        self,
        *,
        write_centrality_penalty: float = 0.15,
        protected_penalty: float = 1.0,
    ) -> None:
        self.write_centrality_penalty = write_centrality_penalty
        self.protected_penalty = protected_penalty

    def rerank(self, goal_text: str, candidates: list[RerankFeatures]) -> list[RerankResult]:
        goal_tokens = {token.lower() for token in goal_text.split() if len(token) > 2}
        results: list[RerankResult] = []
        for item in candidates:
            reasons: list[str] = []
            score = item.rrf_score + 0.35 * item.bm25_score + 0.25 * item.ann_score
            if goal_tokens and item.chunk.qualified_name:
                overlap = len(goal_tokens & set(item.chunk.qualified_name.lower().split("_")))
                score += 0.1 * overlap
                if overlap:
                    reasons.append("symbol_overlap")
            if item.chunk.pagerank is not None:
                score -= self.write_centrality_penalty * float(item.chunk.pagerank)
                reasons.append("centrality_penalty")
            if item.chunk.sensitivity != SensitivityLabel.NORMAL:
                score -= self.protected_penalty
                reasons.append("protected_penalty")
            results.append(RerankResult(chunk_id=item.chunk.chunk_id, score=score, reasons=reasons))
        results.sort(key=lambda row: row.score, reverse=True)
        return results
