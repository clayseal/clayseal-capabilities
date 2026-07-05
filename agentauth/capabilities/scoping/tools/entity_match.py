"""Token-overlap entity resolution against a small, enumerable entity directory.

Deliberately does not use the BM25/ANN/RRF hybrid retrieval pipeline in
`scoping/retrieval/` -- that pipeline earns its keep on a large, noisy code
corpus where naive substring matching badly under/over-matches. Resolving a
name like "Camille" against a few thousand structured employee records is a
categorically smaller, simpler fuzzy record-lookup problem. `reciprocal_rank_fusion`
is reused (it's generic over ranked id lists) to merge the two matching
strategies below; the rest of the retrieval stack is not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from agentauth.capabilities.scoping.retrieval.rrf import reciprocal_rank_fusion
from agentauth.capabilities.scoping.tools.entity_index import ToolEntityIndex

_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,}")


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


@dataclass(frozen=True)
class EntityMatch:
    entity_id: str
    score: float
    matched_on: str
    reasons: list[str]


def _entity_haystacks(index: ToolEntityIndex) -> dict[str, list[str]]:
    haystacks: dict[str, list[str]] = {}
    for entity in index.entities:
        names = [entity.display_name, entity.entity_id, *entity.aliases]
        haystacks[entity.entity_id] = [name.lower() for name in names]
    return haystacks


_MIN_OVERLAP_FRACTION = 0.5


def _token_overlap_rank(query_tokens: set[str], index: ToolEntityIndex) -> list[str]:
    """Ranked by what fraction of the *entity's own* name tokens appear in
    the query, not raw overlap count -- and a minimum fraction is enforced
    here, before RRF fusion, not after. RRF fuses by rank position only, so
    a weak single-word overlap against a long, multi-word group name (e.g.
    matching just "bonus" out of "Sales bonus population") and a strong
    full-name match can end up with nearly identical fused scores despite a
    real difference in match quality -- that quality signal has to be
    enforced before fusion discards it, not by raising the fused-score
    threshold afterward (which was tried and just shifts the same problem).
    """
    scored: list[tuple[str, float]] = []
    for entity in index.entities:
        entity_tokens = set()
        for name in (entity.display_name, *entity.aliases):
            entity_tokens.update(_tokenize(name))
        if not entity_tokens:
            continue
        overlap = len(query_tokens & entity_tokens)
        if not overlap:
            continue
        fraction = overlap / len(entity_tokens)
        if fraction >= _MIN_OVERLAP_FRACTION:
            scored.append((entity.entity_id, fraction))
    scored.sort(key=lambda item: item[1], reverse=True)
    return [entity_id for entity_id, _score in scored]


def _substring_rank(query_text: str, index: ToolEntityIndex) -> list[str]:
    lowered = query_text.lower()
    haystacks = _entity_haystacks(index)
    scored: list[tuple[str, int]] = []
    for entity_id, names in haystacks.items():
        best = 0
        for name in names:
            if not name:
                continue
            if name in lowered or lowered in name:
                best = max(best, len(name))
        if best:
            scored.append((entity_id, best))
    scored.sort(key=lambda item: item[1], reverse=True)
    return [entity_id for entity_id, _score in scored]


def resolve_target_entities(
    query_text: str,
    index: ToolEntityIndex,
    *,
    top_k: int = 5,
    min_score: float = 0.01,
) -> list[EntityMatch]:
    """``min_score`` is a low floor, not a real precision filter -- both
    ``_token_overlap_rank`` and ``_substring_rank`` already only emit an
    entity when it had a genuine nonzero match, so anything reaching the
    fused output has already cleared a real bar. It exists mainly to guard
    against RRF's own scoring scale: with the default ``k=20``, a single
    rank-0 hit in only one of the two ranked lists scores ``1/21 ~= 0.048``
    -- a threshold much above that (an earlier version used 0.05) silently
    excludes exactly the common case of a partial/first-name-only match.
    """
    if not query_text or not index.entities:
        return []

    query_tokens = set(_tokenize(query_text))
    token_ranked = _token_overlap_rank(query_tokens, index)
    substring_ranked = _substring_rank(query_text, index)

    fused = reciprocal_rank_fusion(
        [token_ranked, substring_ranked],
        sources=["token_overlap", "substring"],
    )

    entities_by_id = index.entities_by_id()
    matches: list[EntityMatch] = []
    for candidate in fused:
        if candidate.score < min_score:
            continue
        entity = entities_by_id.get(candidate.chunk_id)
        if entity is None:
            continue
        matches.append(
            EntityMatch(
                entity_id=candidate.chunk_id,
                score=candidate.score,
                matched_on=candidate.source,
                reasons=[f"{candidate.source} match against {entity.display_name!r}"],
            )
        )
    return matches[:top_k]
