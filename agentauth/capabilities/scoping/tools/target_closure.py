from __future__ import annotations

from dataclasses import dataclass, field

from agentauth.capabilities.scoping._bfs import expand_frontier


@dataclass
class TargetClosurePolicy:
    membership_depth: int = 1
    max_expanded_entities: int = 500


@dataclass
class TargetClosure:
    seed_entities: set[str] = field(default_factory=set)
    expanded_entities: set[str] = field(default_factory=set)
    blocked_oversized_groups: set[str] = field(default_factory=set)


def compute_target_closure(
    *,
    seed_entities: set[str],
    membership_edges: list[tuple[str, str]],
    policy: TargetClosurePolicy | None = None,
) -> TargetClosure:
    """Expand named groups in ``seed_entities`` to their bounded member set.

    Mirrors ``compute_file_closure``'s import-graph expansion, over
    group-membership edges (``group_id -> member_entity_id``) instead. A
    seed group whose own direct membership exceeds
    ``policy.max_expanded_entities`` is excluded from expansion entirely
    (fail closed) rather than silently truncated by BFS visit order -- an
    arbitrary partial subset of an oversized group is not a defensible
    "expected targets" set.
    """
    cfg = policy or TargetClosurePolicy()
    seeds = {entity_id for entity_id in seed_entities if entity_id}

    direct_member_counts: dict[str, int] = {}
    for src, _dst in membership_edges:
        direct_member_counts[src] = direct_member_counts.get(src, 0) + 1

    blocked = {
        seed
        for seed in seeds
        if direct_member_counts.get(seed, 0) > cfg.max_expanded_entities
    }
    usable_edges = [(src, dst) for src, dst in membership_edges if src not in blocked]
    expandable_seeds = seeds - blocked

    expanded = expand_frontier(
        expandable_seeds,
        edges=usable_edges,
        depth=cfg.membership_depth,
        cap=cfg.max_expanded_entities,
    )
    # Blocked seeds remain named (the group id itself was explicitly seeded)
    # even though their membership isn't expanded into.
    expanded |= blocked

    return TargetClosure(
        seed_entities=seeds,
        expanded_entities=expanded,
        blocked_oversized_groups=blocked,
    )
