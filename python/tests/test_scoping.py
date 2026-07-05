from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from agentauth.capabilities.scoping import (
    build_capability_lease,
    build_repo_chunk_index,
    check_repo_path_allowed,
    compute_file_closure,
)
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.capabilities.scoping.models import SensitivityLabel


@pytest.fixture()
def sample_repo(tmp_path: Path) -> Path:
    (tmp_path / "swe_triage").mkdir()
    (tmp_path / "swe_triage" / "parser.py").write_text(
        textwrap.dedent(
            '''
            """Parser module."""
            from swe_triage.auth import verify_token

            def parse_ticket(raw: str) -> dict:
                verify_token(raw)
                return {"ok": True}
            '''
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "swe_triage" / "auth.py").write_text(
        textwrap.dedent(
            '''
            def verify_token(raw: str) -> bool:
                return bool(raw)
            '''
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    return tmp_path


def test_build_repo_chunk_index_chunks_and_import_graph(sample_repo: Path) -> None:
    index = build_repo_chunk_index(sample_repo)
    assert index.chunks
    assert any(chunk.qualified_name == "parse_ticket" for chunk in index.chunks)
    assert ("swe_triage/parser.py", "swe_triage/auth.py") in index.import_edges
    assert index.file_pagerank["swe_triage/auth.py"] >= 0


def test_build_capability_lease_scopes_parser_goal(sample_repo: Path) -> None:
    index = build_repo_chunk_index(sample_repo)
    goal = GoalSpec(query_id="q-1", summary="Fix parse_ticket bug in parser")
    lease = build_capability_lease(index, goal, top_k=3)
    assert "swe_triage/parser.py" in lease.write_files
    assert "swe_triage/auth.py" in lease.read_files
    assert "pyproject.toml" in lease.read_files
    allowed, _reason = check_repo_path_allowed("swe_triage/parser.py", lease, write=True)
    assert allowed
    denied, reason = check_repo_path_allowed("swe_triage/auth.py", lease, write=True)
    assert not denied
    assert reason == "out_of_scope"


def test_explicit_allow_resource_permits_protected_write(sample_repo: Path) -> None:
    index = build_repo_chunk_index(sample_repo)
    goal = GoalSpec(
        query_id="q-2",
        summary="Update auth verify_token",
        allow_resources=["repo://swe_triage/auth.py"],
    )
    lease = build_capability_lease(index, goal, top_k=2)
    assert "swe_triage/auth.py" in lease.write_files
    ok, _ = check_repo_path_allowed("swe_triage/auth.py", lease, write=True)
    assert ok


def test_check_repo_path_rejects_traversal(sample_repo: Path) -> None:
    index = build_repo_chunk_index(sample_repo)
    goal = GoalSpec(query_id="q-3", summary="Fix parse_ticket bug in parser")
    lease = build_capability_lease(index, goal, top_k=3)
    denied, reason = check_repo_path_allowed("../swe_triage/auth.py", lease, write=False)
    assert not denied
    assert reason == "invalid_path"
    denied2, reason2 = check_repo_path_allowed("swe_triage/../swe_triage/auth.py", lease, write=False)
    assert not denied2
    assert reason2 == "invalid_path"


def test_capability_lease_resource_scope_uses_repo_uri(sample_repo: Path) -> None:
    index = build_repo_chunk_index(sample_repo)
    goal = GoalSpec(query_id="q-4", summary="Fix parse_ticket bug in parser")
    lease = build_capability_lease(index, goal, top_k=3)
    entries = lease.resource_scope_entries()
    assert any(entry.startswith("repo://swe_triage/parser.py") for entry in entries)
    assert not any(entry.startswith("file:") for entry in entries)


def test_compute_file_closure_respects_protected_write_cap() -> None:
    closure = compute_file_closure(
        seed_files={"src/main.py"},
        import_edges=[("src/main.py", "auth/secret.py")],
        build_manifest_files=set(),
        file_sensitivity={"auth/secret.py": SensitivityLabel.PROTECTED},
        explicit_allow_files=set(),
    )
    assert "auth/secret.py" in closure.read_files
    assert "auth/secret.py" not in closure.write_files
