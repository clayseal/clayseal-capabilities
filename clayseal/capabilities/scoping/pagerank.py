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
