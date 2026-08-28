"""The types dynamic scoping is made of.

A `RepoChunk` is a piece of a repository with an identity, a kind and a
sensitivity label; a `RepoChunkIndex` is many of them; a `CapabilityLease` is the
narrowed grant a session actually runs under.

`SensitivityLabel` is the field with consequences. It is what marks a chunk as
something a lease should not casually include, and it comes from
`labels.py` rules over the path rather than from the file's contents, because
reading contents to decide whether contents are sensitive is a circular
authority: the read has already happened.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from clayseal.core.hash_util import hash_canonical_json


class ChunkKind(str, Enum):
    SYMBOL = "symbol"
    FILE_PREAMBLE = "file_preamble"
    CONFIG_BLOCK = "config_block"
    WINDOW = "window"


class SensitivityLabel(str, Enum):
    NORMAL = "normal"
    PROTECTED = "protected"
    HIGHLY_PROTECTED = "highly_protected"


@dataclass
class RepoChunk:
    chunk_id: str
    repo_sha: str
    file_path: str
    start_line: int
    end_line: int
    language: str
    kind: ChunkKind
    qualified_name: str | None = None
    text: str = ""
    content_hash: str = ""
    sensitivity: SensitivityLabel = SensitivityLabel.NORMAL
    subsystem_tags: list[str] = field(default_factory=list)
    pagerank: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "repo_sha": self.repo_sha,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "language": self.language,
            "kind": self.kind.value,
            "qualified_name": self.qualified_name,
            "content_hash": self.content_hash,
            "sensitivity": self.sensitivity.value,
            "subsystem_tags": list(self.subsystem_tags),
            "pagerank": self.pagerank,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> RepoChunk:
        return cls(
            chunk_id=str(raw["chunk_id"]),
            repo_sha=str(raw["repo_sha"]),
            file_path=str(raw["file_path"]),
            start_line=int(raw["start_line"]),
            end_line=int(raw["end_line"]),
            language=str(raw.get("language", "unknown")),
            kind=ChunkKind(str(raw.get("kind", ChunkKind.WINDOW.value))),
            qualified_name=raw.get("qualified_name"),
            text=str(raw.get("text", "")),
            content_hash=str(raw.get("content_hash", "")),
            sensitivity=SensitivityLabel(str(raw.get("sensitivity", SensitivityLabel.NORMAL.value))),
            subsystem_tags=[str(item) for item in raw.get("subsystem_tags", [])],
            pagerank=float(raw["pagerank"]) if raw.get("pagerank") is not None else None,
        )


def make_chunk_id(
    *,
    repo_sha: str,
    file_path: str,
    kind: ChunkKind,
    qualified_name: str | None = None,
    window_index: int | None = None,
) -> str:
    key: dict[str, Any] = {
        "repo_sha": repo_sha,
        "file_path": file_path.replace("\\", "/"),
        "kind": kind.value,
    }
    if qualified_name:
        key["qualified_name"] = qualified_name
    if window_index is not None:
        key["window_index"] = window_index
    return hash_canonical_json(key)


@dataclass
class RepoChunkIndex:
    repo_sha: str
    repo_root: str
    chunks: list[RepoChunk] = field(default_factory=list)
    import_edges: list[tuple[str, str]] = field(default_factory=list)
    file_pagerank: dict[str, float] = field(default_factory=dict)
    build_manifest_files: list[str] = field(default_factory=list)

    def chunks_by_id(self) -> dict[str, RepoChunk]:
        return {chunk.chunk_id: chunk for chunk in self.chunks}

    def chunks_for_file(self, file_path: str) -> list[RepoChunk]:
        normalized = file_path.replace("\\", "/")
        return [chunk for chunk in self.chunks if chunk.file_path == normalized]

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo_sha": self.repo_sha,
            "repo_root": self.repo_root,
            "chunks": [chunk.to_dict() for chunk in self.chunks],
            "import_edges": [{"from": src, "to": dst} for src, dst in self.import_edges],
            "file_pagerank": dict(self.file_pagerank),
            "build_manifest_files": list(self.build_manifest_files),
        }


@dataclass
class CapabilityLease:
    """File-level read/write allowlists minted for one goal."""

    query_id: str
    repo_sha: str
    seed_chunk_ids: list[str]
    read_files: set[str] = field(default_factory=set)
    write_files: set[str] = field(default_factory=set)
    explicit_allow_resources: set[str] = field(default_factory=set)
    metric_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_id": self.query_id,
            "repo_sha": self.repo_sha,
            "seed_chunk_ids": list(self.seed_chunk_ids),
            "read_files": sorted(self.read_files),
            "write_files": sorted(self.write_files),
            "explicit_allow_resources": sorted(self.explicit_allow_resources),
            "metric_id": self.metric_id,
        }

    def resource_scope_entries(self) -> list[str]:
        """Entries for ``AuthorityContext.resource_scope`` (gateway ``repo://`` refs)."""
        entries: list[str] = []
        for path in sorted(self.write_files | self.read_files):
            normalized = path.replace("\\", "/").lstrip("/")
            if normalized:
                entries.append(f"repo://{normalized}")
        for resource in sorted(self.explicit_allow_resources):
            if resource.startswith(("repo://", "file:", "net:")):
                entries.append(resource)
            else:
                entries.append(f"repo://{resource.lstrip('/')}")
        return sorted(set(entries))
