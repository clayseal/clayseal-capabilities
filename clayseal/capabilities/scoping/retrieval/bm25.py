from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from clayseal.capabilities.scoping.models import RepoChunk


def _tokenize(text: str) -> list[str]:
    return re.findall(r"[A-Za-z_][A-Za-z0-9_]{1,}", text.lower())


@dataclass
class BM25Index:
    documents: list[str]
    doc_tokens: list[list[str]]
    df: Counter[str]
    avgdl: float
    k1: float = 1.2
    b: float = 0.75

    @classmethod
    def from_chunks(cls, chunks: list[RepoChunk]) -> BM25Index:
        docs: list[str] = []
        tokenized: list[list[str]] = []
        for chunk in chunks:
            body = " ".join(
                filter(
                    None,
                    [chunk.qualified_name or "", chunk.file_path, chunk.text],
                )
            )
            docs.append(body)
            tokenized.append(_tokenize(body))
        df: Counter[str] = Counter()
        for tokens in tokenized:
            df.update(set(tokens))
        avgdl = sum(len(tokens) for tokens in tokenized) / max(1, len(tokenized))
        return cls(documents=docs, doc_tokens=tokenized, df=df, avgdl=avgdl)

    def score_query(self, query: str) -> list[float]:
        q_tokens = _tokenize(query)
        if not q_tokens:
            return [0.0] * len(self.doc_tokens)
        n = len(self.doc_tokens)
        scores = [0.0] * n
        for term in q_tokens:
            if term not in self.df:
                continue
            idf = math.log(1 + (n - self.df[term] + 0.5) / (self.df[term] + 0.5))
            for idx, tokens in enumerate(self.doc_tokens):
                tf = tokens.count(term)
                if tf == 0:
                    continue
                dl = len(tokens)
                denom = tf + self.k1 * (1 - self.b + self.b * (dl / self.avgdl))
                scores[idx] += idf * ((tf * (self.k1 + 1)) / denom)
        return scores

    def top_n(self, query: str, n: int) -> list[tuple[int, float]]:
        scores = self.score_query(query)
        ranked = sorted(enumerate(scores), key=lambda item: item[1], reverse=True)
        return [(idx, score) for idx, score in ranked[:n] if score > 0]
