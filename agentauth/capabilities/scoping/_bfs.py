"""Generic bounded BFS over a directed edge list, shared by closure.py (file
import graphs) and tools/target_closure.py (entity/group membership graphs).
"""

from __future__ import annotations

from typing import Iterable


def _successors(node: str, edges: list[tuple[str, str]]) -> set[str]:
    return {dst for src, dst in edges if src == node}


def expand_frontier(
    seeds: Iterable[str],
    *,
    edges: list[tuple[str, str]],
    depth: int,
    cap: int,
) -> set[str]:
    """Bounded breadth-first expansion of ``seeds`` along ``edges``.

    Stops once ``depth`` levels have been walked or ``len(seen) >= cap``,
    whichever comes first. Domain-agnostic: the same routine backs file
    import-closure and entity/group membership-closure.
    """
    seen: set[str] = set(seeds)
    frontier = list(seeds)
    for _ in range(depth):
        if not frontier:
            break
        next_frontier: list[str] = []
        for node in frontier:
            for dst in _successors(node, edges):
                if dst in seen:
                    continue
                seen.add(dst)
                next_frontier.append(dst)
                if len(seen) >= cap:
                    return seen
        frontier = next_frontier
    return seen
