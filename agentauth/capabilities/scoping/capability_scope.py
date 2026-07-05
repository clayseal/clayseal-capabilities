from __future__ import annotations

import re

from agentauth.capabilities.scoping.closure import ClosurePolicy, compute_file_closure
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.capabilities.scoping.models import CapabilityLease, RepoChunk, RepoChunkIndex, SensitivityLabel
from agentauth.capabilities.scoping.retrieval.ann import HashingEmbedder, TextEmbedder, build_ann_index
from agentauth.capabilities.scoping.retrieval.bm25 import BM25Index
from agentauth.capabilities.scoping.retrieval.mmr import maximal_marginal_relevance
from agentauth.capabilities.scoping.retrieval.rerank import DefaultChunkReranker, PartnerReranker, RerankFeatures
from agentauth.capabilities.scoping.retrieval.rrf import reciprocal_rank_fusion

_DEFAULT_TOP_K = 12
_DEFAULT_BM25_CANDIDATES = 64
_DEFAULT_ANN_CANDIDATES = 64
_DEFAULT_TOKEN_CANDIDATES = 64
_DEFAULT_SHORTLIST = 96


def score_chunks_for_goal(
    index: RepoChunkIndex,
    goal: GoalSpec,
    *,
    top_k: int = _DEFAULT_TOP_K,
    n_bm25: int = _DEFAULT_BM25_CANDIDATES,
    n_ann: int = _DEFAULT_ANN_CANDIDATES,
    n_tokens: int = _DEFAULT_TOKEN_CANDIDATES,
    shortlist: int = _DEFAULT_SHORTLIST,
    embedder: TextEmbedder | None = None,
    reranker: PartnerReranker | None = None,
) -> list[RepoChunk]:
    if not index.chunks:
        return []
    bm25 = BM25Index.from_chunks(index.chunks)
    bm25_hits = bm25.top_n(goal.summary, n_bm25)
    bm25_ranked = [index.chunks[idx].chunk_id for idx, _score in bm25_hits]

    embedder_impl = embedder or HashingEmbedder()
    ann_texts = [
        " ".join(
            filter(
                None,
                [
                    chunk.qualified_name,
                    chunk.file_path,
                    chunk.text[:800],
                ],
            )
        )
        for chunk in index.chunks
    ]
    ann_index = build_ann_index(
        chunk_ids=[chunk.chunk_id for chunk in index.chunks],
        texts=ann_texts,
        embedder=embedder_impl,
    )
    ann_hits = ann_index.top_n(goal.summary, n_ann, embedder=embedder_impl)
    ann_ranked = [hit.chunk_id for hit in ann_hits]
    ann_score_map = {hit.chunk_id: hit.score for hit in ann_hits}

    token_hits = _token_match_rank(index.chunks, goal.summary, limit=n_tokens)
    fused = reciprocal_rank_fusion(
        [bm25_ranked, ann_ranked, token_hits],
        k=20,
        sources=["bm25", "ann", "tokens"],
    )
    shortlist_ids = [item.chunk_id for item in fused[:shortlist]]
    by_id = index.chunks_by_id()
    rrf_scores = {item.chunk_id: item.score for item in fused}

    reranker_impl = reranker or DefaultChunkReranker()
    features = []
    bm25_map = {index.chunks[idx].chunk_id: score for idx, score in bm25_hits}
    for chunk_id in shortlist_ids:
        chunk = by_id.get(chunk_id)
        if chunk is None:
            continue
        features.append(
            RerankFeatures(
                chunk=chunk,
                bm25_score=bm25_map.get(chunk_id, 0.0),
                ann_score=ann_score_map.get(chunk_id, 0.0),
                rrf_score=rrf_scores.get(chunk_id, 0.0),
            )
        )
    reranked = reranker_impl.rerank(goal.summary, features)
    score_map = {row.chunk_id: row.score for row in reranked}
    shortlist_chunks = [by_id[cid] for cid in shortlist_ids if cid in by_id]
    return maximal_marginal_relevance(shortlist_chunks, scores=score_map, k=top_k)


def build_capability_lease(
    index: RepoChunkIndex,
    goal: GoalSpec,
    *,
    top_k: int = _DEFAULT_TOP_K,
    closure_policy: ClosurePolicy | None = None,
    embedder: TextEmbedder | None = None,
    reranker: PartnerReranker | None = None,
) -> CapabilityLease:
    selected = score_chunks_for_goal(index, goal, top_k=top_k, embedder=embedder, reranker=reranker)
    seed_files = {chunk.file_path for chunk in selected}
    explicit = goal.explicit_allow_files()

    file_sensitivity = {
        chunk.file_path: chunk.sensitivity for chunk in index.chunks
    }
    closure = compute_file_closure(
        seed_files=seed_files | explicit,
        import_edges=index.import_edges,
        build_manifest_files=set(index.build_manifest_files),
        file_sensitivity=file_sensitivity,
        explicit_allow_files=explicit,
        policy=closure_policy,
    )

    reranker_impl = reranker or DefaultChunkReranker()
    return CapabilityLease(
        query_id=goal.query_id,
        repo_sha=index.repo_sha,
        seed_chunk_ids=[chunk.chunk_id for chunk in selected],
        read_files=closure.read_files | explicit,
        write_files=closure.write_files | explicit,
        explicit_allow_resources=set(goal.allow_resources),
        metric_id=reranker_impl.metric_id,
    )


def apply_lease_to_authority(authority: object, lease: CapabilityLease) -> None:
    """Bind a minted lease onto an ``AuthorityContext`` for gateway enforcement."""
    authority.lease_query_id = lease.query_id  # type: ignore[attr-defined]


def _token_match_rank(chunks: list[RepoChunk], query: str, *, limit: int) -> list[str]:
    tokens = [token.lower() for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", query)]
    if not tokens:
        return []
    scored: list[tuple[str, int]] = []
    for chunk in chunks:
        hay = " ".join(
            filter(None, [chunk.qualified_name, chunk.file_path, chunk.text[:500]])
        ).lower()
        score = sum(1 for token in tokens if token in hay)
        if score:
            scored.append((chunk.chunk_id, score))
    scored.sort(key=lambda item: item[1], reverse=True)
    return [chunk_id for chunk_id, _score in scored[:limit]]
