from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Protocol


class TextEmbedder(Protocol):
    metric_id: str
    dim: int

    def embed(self, texts: list[str]) -> list[list[float]]: ...


@dataclass(frozen=True)
class HashingEmbedder:
    """
    Deterministic embedder used as a v1 fallback when no partner embedder exists.

    This is intentionally simple: tokenize by whitespace-ish boundaries, hash tokens into a fixed
    dimensional space, L2-normalize, and use cosine similarity.
    """

    dim: int = 256
    metric_id: str = "hashing-embedder-v1"

    def embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []

        mat: list[list[float]] = [[0.0 for _ in range(self.dim)] for _ in range(len(texts))]
        for row, text in enumerate(texts):
            for token in _tokens(text):
                digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
                h = int.from_bytes(digest, "little", signed=False)
                idx = h % self.dim
                sign = -1.0 if (h >> 63) & 1 else 1.0
                mat[row][idx] += sign

        _l2_normalize_inplace(mat)
        return mat


@dataclass(frozen=True)
class AnnHit:
    chunk_id: str
    score: float


@dataclass
class CosineAnnIndex:
    """Brute-force cosine index (dependency-free)."""

    chunk_ids: list[str]
    vectors: list[list[float]]  # shape: (N, D), L2-normalized

    @classmethod
    def from_texts(
        cls,
        *,
        chunk_ids: list[str],
        texts: list[str],
        embedder: TextEmbedder,
    ) -> CosineAnnIndex:
        if len(chunk_ids) != len(texts):
            raise ValueError("chunk_ids and texts must have the same length")
        vecs = embedder.embed(texts)
        if len(vecs) != len(texts):
            raise ValueError("embedder returned unexpected length")
        if vecs and len(vecs[0]) != embedder.dim:
            raise ValueError("embedder returned unexpected dim")
        return cls(chunk_ids=list(chunk_ids), vectors=vecs)

    def top_n(self, query_text: str, n: int, *, embedder: TextEmbedder) -> list[AnnHit]:
        if n <= 0 or not self.chunk_ids:
            return []
        q = embedder.embed([query_text])
        if len(q) != 1:
            raise ValueError("embedder returned unexpected query length")
        qv = q[0]
        if len(qv) != len(self.vectors[0]):
            raise ValueError("embedder returned unexpected query dim")

        hits: list[AnnHit] = []
        for idx, vec in enumerate(self.vectors):
            score = 0.0
            for a, b in zip(vec, qv, strict=True):
                score += a * b
            hits.append(AnnHit(chunk_id=self.chunk_ids[idx], score=score))
        hits.sort(key=lambda hit: hit.score, reverse=True)
        return hits[: min(int(n), len(hits))]


@dataclass
class HnswAnnIndex:
    """Optional HNSW index (requires `hnswlib` + `numpy`)."""

    chunk_ids: list[str]
    dim: int
    _index: object

    @classmethod
    def from_texts(
        cls,
        *,
        chunk_ids: list[str],
        texts: list[str],
        embedder: TextEmbedder,
        ef_construction: int = 200,
        m: int = 16,
        ef: int = 64,
    ) -> HnswAnnIndex:
        try:
            import hnswlib  # type: ignore[import-not-found]
            import numpy as np  # type: ignore[import-not-found]
        except Exception as exc:
            raise RuntimeError("hnswlib not available") from exc

        vecs = embedder.embed(texts)
        data = np.array(vecs, dtype=np.float32)
        if data.ndim != 2 or data.shape[0] != len(chunk_ids) or data.shape[1] != embedder.dim:
            raise ValueError("embedder returned unexpected embedding matrix shape")

        index = hnswlib.Index(space="cosine", dim=embedder.dim)
        index.init_index(
            max_elements=len(chunk_ids),
            ef_construction=int(ef_construction),
            M=int(m),
        )
        index.add_items(data, np.arange(len(chunk_ids)))
        index.set_ef(int(ef))
        return cls(chunk_ids=list(chunk_ids), dim=int(embedder.dim), _index=index)

    def top_n(self, query_text: str, n: int, *, embedder: TextEmbedder) -> list[AnnHit]:
        if n <= 0 or not self.chunk_ids:
            return []
        try:
            import numpy as np  # type: ignore[import-not-found]
        except Exception as exc:
            raise RuntimeError("numpy not available") from exc

        q = embedder.embed([query_text])
        qv = np.array(q, dtype=np.float32)
        labels, distances = self._index.knn_query(qv, k=min(int(n), len(self.chunk_ids)))  # type: ignore[attr-defined]
        hits: list[AnnHit] = []
        for label, dist in zip(labels[0], distances[0], strict=True):
            # hnswlib cosine distance is typically (1 - cosine_similarity)
            sim = 1.0 - float(dist)
            hits.append(AnnHit(chunk_id=self.chunk_ids[int(label)], score=sim))
        hits.sort(key=lambda hit: hit.score, reverse=True)
        return hits


def build_ann_index(
    *,
    chunk_ids: list[str],
    texts: list[str],
    embedder: TextEmbedder,
) -> CosineAnnIndex | HnswAnnIndex:
    """
    Prefer HNSW when available, fall back to brute-force cosine.

    Only the "HNSW unavailable" signals (missing hnswlib/numpy) trigger the
    fallback; a genuine build error (e.g. a shape/dimension ``ValueError`` from
    a misbehaving embedder) propagates instead of being silently masked.
    """
    try:
        return HnswAnnIndex.from_texts(chunk_ids=chunk_ids, texts=texts, embedder=embedder)
    except (ImportError, RuntimeError):
        return CosineAnnIndex.from_texts(chunk_ids=chunk_ids, texts=texts, embedder=embedder)


def _tokens(text: str) -> list[str]:
    # Keep this deterministic and cheap; callers can include identifiers/paths alongside text.
    return [tok.lower() for tok in text.split() if len(tok) >= 2]


def _l2_normalize_inplace(mat: list[list[float]]) -> None:
    for row in mat:
        norm = math.sqrt(sum(v * v for v in row))
        if norm <= 0:
            continue
        inv = 1.0 / norm
        for i, v in enumerate(row):
            row[i] = v * inv
