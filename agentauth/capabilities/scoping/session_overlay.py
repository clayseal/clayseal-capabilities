"""DP-8: Incremental updates, session overlay for changed files.

The base ``RepoChunkIndex`` is frozen at ``repo@sha`` when the goal starts.
During the session, the agent edits files.  This module provides a
``SessionChunkOverlay`` that re-chunks only changed files and patches
the index without a full rebuild.

Two layers:
    RepoChunkIndex, immutable base (built at goal start)
    SessionChunkOverlay, append + patch during the session
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from agentauth.capabilities.scoping.chunkers import chunk_file
from agentauth.capabilities.scoping.imports_graph import extract_import_edges
from agentauth.capabilities.scoping.models import RepoChunk, RepoChunkIndex


@dataclass
class OverlayEntry:
    chunk: RepoChunk
    supersedes: str | None = None


@dataclass
class SessionChunkOverlay:
    """Incremental overlay on top of a frozen ``RepoChunkIndex`` (DP-8).

    Usage::

        overlay = SessionChunkOverlay(base_index)
        overlay.update_file("src/main.py", new_text)
        merged = overlay.merged_index()  # base + overlay
    """

    base: RepoChunkIndex
    entries: dict[str, OverlayEntry] = field(default_factory=dict)
    removed_chunk_ids: set[str] = field(default_factory=set)
    _extra_import_edges: list[tuple[str, str]] = field(default_factory=list)

    def update_file(self, rel_path: str, new_text: str | None = None) -> list[RepoChunk]:
        """Re-chunk a single changed file and update the overlay.

        If ``new_text`` is None, reads the file from disk using the base
        index's ``repo_root``.  Returns the new chunks for the file.
        """
        rel = rel_path.replace("\\", "/")
        root = Path(self.base.repo_root)
        abs_path = root / rel

        if new_text is None:
            if not abs_path.is_file():
                self._remove_file_chunks(rel)
                return []
            new_text = abs_path.read_text(encoding="utf-8", errors="replace")
        else:
            abs_path.parent.mkdir(parents=True, exist_ok=True)
            abs_path.write_text(new_text, encoding="utf-8")

        old_ids = {c.chunk_id for c in self.base.chunks if c.file_path == rel}

        new_chunks = chunk_file(
            repo_sha=self.base.repo_sha,
            repo_root=root,
            file_path=abs_path,
        )

        new_ids = {c.chunk_id for c in new_chunks}
        for old_id in old_ids:
            if old_id not in new_ids:
                self.removed_chunk_ids.add(old_id)
                self.entries.pop(old_id, None)
        for chunk in new_chunks:
            supersedes = chunk.chunk_id if chunk.chunk_id in old_ids else None
            self.entries[chunk.chunk_id] = OverlayEntry(
                chunk=chunk, supersedes=supersedes
            )
            self.removed_chunk_ids.discard(chunk.chunk_id)

        self._recompute_import_edges_for_file(rel, new_text)
        return new_chunks

    def _remove_file_chunks(self, rel: str) -> None:
        for chunk in self.base.chunks:
            if chunk.file_path == rel:
                self.removed_chunk_ids.add(chunk.chunk_id)
                self.entries.pop(chunk.chunk_id, None)

    def _recompute_import_edges_for_file(self, rel: str, text: str) -> None:
        self._extra_import_edges = [
            e for e in self._extra_import_edges if e[0] != rel
        ]
        root = Path(self.base.repo_root)
        new_edges = extract_import_edges(
            repo_root=root,
            file_paths=[rel],
            file_text={rel: text},
        )
        self._extra_import_edges.extend(new_edges)

    def merged_chunks(self) -> list[RepoChunk]:
        """All chunks: base (minus removed) + overlay entries."""
        overlay_ids = set(self.entries.keys())
        result: list[RepoChunk] = []
        for chunk in self.base.chunks:
            if chunk.chunk_id in self.removed_chunk_ids:
                continue
            if chunk.chunk_id in overlay_ids:
                result.append(self.entries[chunk.chunk_id].chunk)
            else:
                result.append(chunk)
        for cid, entry in self.entries.items():
            if cid not in {c.chunk_id for c in result}:
                result.append(entry.chunk)
        return result

    def merged_import_edges(self) -> list[tuple[str, str]]:
        """Import edges: base (minus edges from updated files) + overlay edges."""
        updated_files = {
            e.chunk.file_path for e in self.entries.values()
        } | {
            c.file_path
            for c in self.base.chunks
            if c.chunk_id in self.removed_chunk_ids
        }
        base_edges = [
            e for e in self.base.import_edges if e[0] not in updated_files
        ]
        return base_edges + list(self._extra_import_edges)

    def merged_index(self) -> RepoChunkIndex:
        """Build a merged index (base + overlay) for retrieval / scoping."""
        chunks = self.merged_chunks()
        edges = self.merged_import_edges()
        return RepoChunkIndex(
            repo_sha=self.base.repo_sha,
            repo_root=self.base.repo_root,
            chunks=chunks,
            import_edges=edges,
            file_pagerank=dict(self.base.file_pagerank),
            build_manifest_files=list(self.base.build_manifest_files),
        )

    @property
    def changed_files(self) -> set[str]:
        return {e.chunk.file_path for e in self.entries.values()}
