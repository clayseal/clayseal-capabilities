"""DP-12: ripgrep candidate channel for goal-token search.

Extracts tokens (identifiers, error strings) from the goal and runs
``rg`` (ripgrep) to find matching files/lines.  Returns chunk IDs
ranked by match count, feeding into the RRF fusion pipeline.

This channel is optional and degrades gracefully when ``rg`` is not
installed — it returns an empty list.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from agentauth.capabilities.scoping.models import RepoChunk


_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")

# Max lines rg can return per token (budget)
_MAX_MATCHES_PER_TOKEN = 50
_RG_TIMEOUT_SECONDS = 5


def _has_rg() -> bool:
    return shutil.which("rg") is not None


def extract_goal_tokens(goal_text: str) -> list[str]:
    """Extract searchable tokens from a goal string."""
    return list(dict.fromkeys(_TOKEN_RE.findall(goal_text)))


def rg_search_files(
    tokens: list[str],
    repo_root: str | Path,
    *,
    max_matches: int = _MAX_MATCHES_PER_TOKEN,
    timeout: int = _RG_TIMEOUT_SECONDS,
) -> dict[str, int]:
    """Run rg for each token and return {file_path: match_count}.

    Returns an empty dict when ``rg`` is not available.
    """
    if not _has_rg() or not tokens:
        return {}

    root = str(Path(repo_root).resolve())
    file_scores: dict[str, int] = {}

    for token in tokens[:20]:  # cap tokens to avoid runaway
        try:
            result = subprocess.run(
                [
                    "rg",
                    "--files-with-matches",
                    "--no-heading",
                    "--max-count", str(max_matches),
                    "--type-add", "source:*.{py,ts,tsx,js,jsx,go,rs,yaml,yml,tf,hcl}",
                    "--type", "source",
                    "--", token,
                ],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            continue

        if result.returncode not in (0, 1):  # 1 = no matches
            continue

        for line in result.stdout.strip().splitlines():
            rel = line.strip()
            if rel:
                file_scores[rel] = file_scores.get(rel, 0) + 1

    return file_scores


def rg_rank_chunks(
    chunks: list[RepoChunk],
    goal_text: str,
    repo_root: str | Path,
    *,
    limit: int = 64,
) -> list[str]:
    """Run rg for goal tokens and rank chunk IDs by file match count.

    Returns a list of chunk_ids ordered by descending rg match score.
    """
    tokens = extract_goal_tokens(goal_text)
    file_scores = rg_search_files(tokens, repo_root)
    if not file_scores:
        return []

    scored: list[tuple[str, int]] = []
    for chunk in chunks:
        score = file_scores.get(chunk.file_path, 0)
        if score > 0:
            scored.append((chunk.chunk_id, score))

    scored.sort(key=lambda item: item[1], reverse=True)
    return [chunk_id for chunk_id, _ in scored[:limit]]
