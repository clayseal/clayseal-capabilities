"""Dynamic capability scoping: chunk index, graph, retrieval, and lease construction."""

from agentauth.capabilities.scoping.capability_scope import build_capability_lease, score_chunks_for_goal, apply_lease_to_authority
from agentauth.capabilities.scoping.closure import ClosurePolicy, compute_file_closure
from agentauth.capabilities.scoping.enforcement import (
    check_repo_path_allowed,
    normalize_repo_path,
    resource_ref_to_repo_path,
)
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.capabilities.scoping.index_builder import build_repo_chunk_index
from agentauth.capabilities.scoping.models import CapabilityLease, RepoChunk, RepoChunkIndex, SensitivityLabel
from agentauth.capabilities.scoping.exploration_budget import ExplorationBudget, ExplorationBudgetConfig
from agentauth.capabilities.scoping.retrieval.rerank import DefaultChunkReranker, PartnerReranker
from agentauth.capabilities.scoping.session_overlay import SessionChunkOverlay

__all__ = [
    "CapabilityLease",
    "ClosurePolicy",
    "DefaultChunkReranker",
    "ExplorationBudget",
    "ExplorationBudgetConfig",
    "GoalSpec",
    "PartnerReranker",
    "RepoChunk",
    "RepoChunkIndex",
    "SensitivityLabel",
    "SessionChunkOverlay",
    "apply_lease_to_authority",
    "build_capability_lease",
    "build_repo_chunk_index",
    "check_repo_path_allowed",
    "compute_file_closure",
    "normalize_repo_path",
    "resource_ref_to_repo_path",
    "score_chunks_for_goal",
]
