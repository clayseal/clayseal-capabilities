"""Which files the repository itself treats as central.

PageRank over the import graph, used as one ranking signal among several. It
answers "what does the rest of the codebase depend on", which is a different
question from "what does this goal mention" and catches the file a task needs
without naming.

A ranking signal only. It contributes to what a lease is built from, never to
what a lease permits.
"""
from __future__ import annotations

from collections import defaultdict


def pagerank_file_graph(
    edges: list[tuple[str, str]],
    *,
    damping: float = 0.85,
    iterations: int = 20,
) -> dict[str, float]:
    nodes: set[str] = set()
    for src, dst in edges:
        nodes.add(src)
        nodes.add(dst)
    if not nodes:
        return {}

    out_neighbors: dict[str, list[str]] = defaultdict(list)
    in_neighbors: dict[str, list[str]] = defaultdict(list)
    for src, dst in edges:
        out_neighbors[src].append(dst)
        in_neighbors[dst].append(src)

    scores = {node: 1.0 / len(nodes) for node in nodes}
    for _ in range(iterations):
        next_scores: dict[str, float] = {}
        for node in nodes:
            incoming = in_neighbors.get(node, [])
            if not incoming:
                rank = (1.0 - damping) / len(nodes)
            else:
                rank = (1.0 - damping) / len(nodes)
                for src in incoming:
                    outs = out_neighbors.get(src, [])
                    if outs:
                        rank += damping * (scores[src] / len(outs))
            next_scores[node] = rank
        scores = next_scores
    return scores
