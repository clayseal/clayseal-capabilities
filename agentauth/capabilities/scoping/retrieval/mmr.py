from __future__ import annotations

from agentauth.capabilities.scoping.models import RepoChunk


def maximal_marginal_relevance(
    chunks: list[RepoChunk],
    *,
    scores: dict[str, float],
    k: int,
    lambda_mult: float = 0.7,
) -> list[RepoChunk]:
    """Greedy MMR using file_path Jaccard as cheap diversity proxy."""
    remaining = list(chunks)
    selected: list[RepoChunk] = []
    while remaining and len(selected) < k:
        best: RepoChunk | None = None
        best_score = float("-inf")
        for candidate in remaining:
            relevance = scores.get(candidate.chunk_id, 0.0)
            if not selected:
                mmr = relevance
            else:
                max_sim = max(_file_similarity(candidate, picked) for picked in selected)
                mmr = lambda_mult * relevance - (1.0 - lambda_mult) * max_sim
            if mmr > best_score:
                best_score = mmr
                best = candidate
        if best is None:
            break
        selected.append(best)
        remaining.remove(best)
    return selected


def _file_similarity(a: RepoChunk, b: RepoChunk) -> float:
    if a.file_path == b.file_path:
        return 1.0
    a_parts = set(a.file_path.split("/"))
    b_parts = set(b.file_path.split("/"))
    if not a_parts or not b_parts:
        return 0.0
    return len(a_parts & b_parts) / len(a_parts | b_parts)
