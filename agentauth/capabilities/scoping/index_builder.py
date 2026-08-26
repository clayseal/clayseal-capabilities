from __future__ import annotations

from pathlib import Path

from agentauth.capabilities.scoping.chunkers import chunk_file
from agentauth.capabilities.scoping.imports_graph import extract_import_edges, is_build_manifest
from agentauth.capabilities.scoping.models import RepoChunkIndex
from agentauth.capabilities.scoping.pagerank import pagerank_file_graph
from agentauth.capabilities.scoping.reference_edges import load_reference_edges
from agentauth.core.hash_util import sha256_hex

_SKIP_DIR_NAMES = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    ".mypy_cache",
}

_SOURCE_SUFFIXES = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".yaml",
    ".yml",
    ".tf",
    ".hcl",
    ".md",
    ".json",
}


def _repo_content_sha(repo_root: Path, files: list[str]) -> str:
    digest = sha256_hex(b"")
    for rel in sorted(files):
        data = (repo_root / rel).read_bytes()
        digest = sha256_hex(f"{rel}:{sha256_hex(data)}:{digest}".encode())
    return digest


def _iter_source_files(repo_root: Path) -> list[str]:
    paths: list[str] = []
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(repo_root).as_posix()
        if any(part in _SKIP_DIR_NAMES for part in path.parts):
            continue
        if path.suffix.lower() not in _SOURCE_SUFFIXES and not is_build_manifest(rel):
            continue
        paths.append(rel)
    return sorted(paths)


def build_repo_chunk_index(
    repo_root: str | Path,
    *,
    repo_sha: str | None = None,
    reference_edges_path: str | Path | None = None,
) -> RepoChunkIndex:
    root = Path(repo_root).resolve()
    files = _iter_source_files(root)
    snapshot_sha = repo_sha or _repo_content_sha(root, files)

    file_text: dict[str, str] = {}
    chunks = []
    for rel in files:
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
        file_text[rel] = text
        chunks.extend(chunk_file(repo_sha=snapshot_sha, repo_root=root, file_path=root / rel))

    edges = extract_import_edges(repo_root=root, file_paths=files, file_text=file_text)
    if reference_edges_path is not None:
        edges = sorted(set(edges) | set(load_reference_edges(reference_edges_path)))
    ranks = pagerank_file_graph(edges)
    manifests = sorted({rel for rel in files if is_build_manifest(rel)})

    for chunk in chunks:
        chunk.pagerank = ranks.get(chunk.file_path)

    return RepoChunkIndex(
        repo_sha=snapshot_sha,
        repo_root=str(root),
        chunks=chunks,
        import_edges=edges,
        file_pagerank=ranks,
        build_manifest_files=manifests,
    )
