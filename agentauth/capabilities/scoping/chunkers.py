from __future__ import annotations

import ast
import re
from pathlib import Path

from agentauth.core.hash_util import sha256_hex

from agentauth.capabilities.scoping.labels import sensitivity_for_path, subsystem_tags_for_path
from agentauth.capabilities.scoping.models import ChunkKind, RepoChunk, make_chunk_id

_WINDOW_LINES = 120
_WINDOW_OVERLAP = 24

_JS_IMPORT_RE = re.compile(
    r"""(?:import\s+(?:[\w*{}\s,]+\s+from\s+)?['"]([^'"]+)['"]|"""
    r"""require\s*\(\s*['"]([^'"]+)['"]\s*\))""",
)


_GO_FUNC_RE = re.compile(
    r"^func\s+(?:\(\s*\w+\s+\*?\w+\s*\)\s+)?(\w+)\s*\(",
    re.MULTILINE,
)
_GO_TYPE_RE = re.compile(
    r"^type\s+(\w+)\s+(?:struct|interface)\s*\{",
    re.MULTILINE,
)

_RUST_FN_RE = re.compile(
    r"^(?:pub(?:\([\w:]+\))?\s+)?(?:async\s+)?fn\s+(\w+)",
    re.MULTILINE,
)
_RUST_STRUCT_RE = re.compile(
    r"^(?:pub(?:\([\w:]+\))?\s+)?(?:struct|enum|trait)\s+(\w+)",
    re.MULTILINE,
)
_RUST_IMPL_RE = re.compile(
    r"^impl(?:<[^>]*>)?\s+(?:(\w+)\s+for\s+)?(\w+)",
    re.MULTILINE,
)


def chunk_file(
    *,
    repo_sha: str,
    repo_root: Path,
    file_path: Path,
) -> list[RepoChunk]:
    rel = file_path.relative_to(repo_root).as_posix()
    text = file_path.read_text(encoding="utf-8", errors="replace")
    suffix = file_path.suffix.lower()
    if suffix == ".py":
        return _chunk_python(repo_sha=repo_sha, rel=rel, text=text)
    if suffix in {".ts", ".tsx", ".js", ".jsx"}:
        return _chunk_js_like(repo_sha=repo_sha, rel=rel, text=text, language=suffix.lstrip("."))
    if suffix == ".go":
        return _chunk_go(repo_sha=repo_sha, rel=rel, text=text)
    if suffix == ".rs":
        return _chunk_rust(repo_sha=repo_sha, rel=rel, text=text)
    if suffix in {".yaml", ".yml"}:
        return _chunk_yaml(repo_sha=repo_sha, rel=rel, text=text)
    if suffix in {".tf", ".hcl"}:
        return _chunk_terraform(repo_sha=repo_sha, rel=rel, text=text)
    return _chunk_sliding_windows(repo_sha=repo_sha, rel=rel, text=text, language="text")


def _chunk_python(*, repo_sha: str, rel: str, text: str) -> list[RepoChunk]:
    lines = text.splitlines()
    chunks: list[RepoChunk] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return _chunk_sliding_windows(repo_sha=repo_sha, rel=rel, text=text, language="python")

    first_def_line: int | None = None
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if first_def_line is None:
                first_def_line = node.lineno
            chunks.append(
                _make_chunk(
                    repo_sha=repo_sha,
                    rel=rel,
                    text=text,
                    start=node.lineno,
                    end=getattr(node, "end_lineno", node.lineno) or node.lineno,
                    language="python",
                    kind=ChunkKind.SYMBOL,
                    qualified_name=node.name,
                )
            )
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        qname = f"{node.name}.{item.name}"
                        chunks.append(
                            _make_chunk(
                                repo_sha=repo_sha,
                                rel=rel,
                                text=text,
                                start=item.lineno,
                                end=getattr(item, "end_lineno", item.lineno) or item.lineno,
                                language="python",
                                kind=ChunkKind.SYMBOL,
                                qualified_name=qname,
                            )
                        )

    preamble_end = (first_def_line - 1) if first_def_line and first_def_line > 1 else min(40, len(lines))
    if preamble_end >= 1:
        chunks.insert(
            0,
            _make_chunk(
                repo_sha=repo_sha,
                rel=rel,
                text=text,
                start=1,
                end=preamble_end,
                language="python",
                kind=ChunkKind.FILE_PREAMBLE,
                qualified_name=None,
            ),
        )
    return chunks or _chunk_sliding_windows(repo_sha=repo_sha, rel=rel, text=text, language="python")


_JS_FUNC_RE = re.compile(
    r"^(?:export\s+)?(?:async\s+)?function\s+(\w+)",
    re.MULTILINE,
)
_JS_ARROW_RE = re.compile(
    r"^(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(",
    re.MULTILINE,
)
_JS_CLASS_RE = re.compile(
    r"^(?:export\s+)?(?:default\s+)?class\s+(\w+)",
    re.MULTILINE,
)
_JS_METHOD_RE = re.compile(
    r"^\s+(?:async\s+)?(\w+)\s*\(",
    re.MULTILINE,
)


def _chunk_js_like(*, repo_sha: str, rel: str, text: str, language: str) -> list[RepoChunk]:
    """Regex-based symbol chunker for JS/TS (DP-2).

    Extracts top-level functions, arrow-const functions, and classes.
    Falls back to sliding windows if no symbols found.
    """
    lines = text.splitlines()
    symbols: list[tuple[str, int]] = []

    for m in _JS_FUNC_RE.finditer(text):
        symbols.append((m.group(1), text[:m.start()].count("\n") + 1))
    for m in _JS_ARROW_RE.finditer(text):
        symbols.append((m.group(1), text[:m.start()].count("\n") + 1))
    for m in _JS_CLASS_RE.finditer(text):
        symbols.append((m.group(1), text[:m.start()].count("\n") + 1))

    if not symbols:
        return _chunk_sliding_windows(repo_sha=repo_sha, rel=rel, text=text, language=language)

    symbols.sort(key=lambda s: s[1])
    chunks: list[RepoChunk] = []

    first_sym_line = symbols[0][1]
    if first_sym_line > 1:
        chunks.append(
            _make_chunk(
                repo_sha=repo_sha, rel=rel, text=text,
                start=1, end=first_sym_line - 1,
                language=language, kind=ChunkKind.FILE_PREAMBLE, qualified_name=None,
            )
        )

    for i, (name, start_line) in enumerate(symbols):
        if i + 1 < len(symbols):
            end_line = symbols[i + 1][1] - 1
        else:
            end_line = len(lines)
        chunks.append(
            _make_chunk(
                repo_sha=repo_sha, rel=rel, text=text,
                start=start_line, end=end_line,
                language=language, kind=ChunkKind.SYMBOL, qualified_name=name,
            )
        )

    return chunks or _chunk_sliding_windows(repo_sha=repo_sha, rel=rel, text=text, language=language)


def _chunk_go(*, repo_sha: str, rel: str, text: str) -> list[RepoChunk]:
    """Regex-based symbol chunker for Go (DP-2)."""
    symbols: list[tuple[str, int]] = []
    for m in _GO_TYPE_RE.finditer(text):
        symbols.append((m.group(1), text[:m.start()].count("\n") + 1))
    for m in _GO_FUNC_RE.finditer(text):
        symbols.append((m.group(1), text[:m.start()].count("\n") + 1))
    return _symbols_to_chunks(
        repo_sha=repo_sha, rel=rel, text=text, language="go", symbols=symbols,
    )


def _chunk_rust(*, repo_sha: str, rel: str, text: str) -> list[RepoChunk]:
    """Regex-based symbol chunker for Rust (DP-2)."""
    symbols: list[tuple[str, int]] = []
    for m in _RUST_STRUCT_RE.finditer(text):
        symbols.append((m.group(1), text[:m.start()].count("\n") + 1))
    for m in _RUST_IMPL_RE.finditer(text):
        name = m.group(2)
        if m.group(1):
            name = f"{m.group(1)}_for_{m.group(2)}"
        symbols.append((f"impl_{name}", text[:m.start()].count("\n") + 1))
    for m in _RUST_FN_RE.finditer(text):
        symbols.append((m.group(1), text[:m.start()].count("\n") + 1))
    return _symbols_to_chunks(
        repo_sha=repo_sha, rel=rel, text=text, language="rust", symbols=symbols,
    )


def _symbols_to_chunks(
    *,
    repo_sha: str,
    rel: str,
    text: str,
    language: str,
    symbols: list[tuple[str, int]],
) -> list[RepoChunk]:
    """Convert a list of (name, start_line) pairs into chunks with preamble."""
    if not symbols:
        return _chunk_sliding_windows(repo_sha=repo_sha, rel=rel, text=text, language=language)
    lines = text.splitlines()
    symbols.sort(key=lambda s: s[1])
    # Deduplicate by line (same line can match multiple patterns)
    seen_lines: set[int] = set()
    deduped: list[tuple[str, int]] = []
    for name, line in symbols:
        if line not in seen_lines:
            seen_lines.add(line)
            deduped.append((name, line))
    symbols = deduped

    chunks: list[RepoChunk] = []
    first_sym_line = symbols[0][1]
    if first_sym_line > 1:
        chunks.append(
            _make_chunk(
                repo_sha=repo_sha, rel=rel, text=text,
                start=1, end=first_sym_line - 1,
                language=language, kind=ChunkKind.FILE_PREAMBLE, qualified_name=None,
            )
        )
    for i, (name, start_line) in enumerate(symbols):
        end_line = symbols[i + 1][1] - 1 if i + 1 < len(symbols) else len(lines)
        chunks.append(
            _make_chunk(
                repo_sha=repo_sha, rel=rel, text=text,
                start=start_line, end=end_line,
                language=language, kind=ChunkKind.SYMBOL, qualified_name=name,
            )
        )
    return chunks or _chunk_sliding_windows(repo_sha=repo_sha, rel=rel, text=text, language=language)


_YAML_TOP_KEY_RE = re.compile(r"^(\w[\w\-]*):", re.MULTILINE)
_GHA_JOB_RE = re.compile(r"^  (\w[\w\-]*):", re.MULTILINE)

_TF_BLOCK_RE = re.compile(
    r'^(resource|data|module|variable|output|locals|provider)\s+"([^"]*)"(?:\s+"([^"]*)")?',
    re.MULTILINE,
)


def _chunk_yaml(*, repo_sha: str, rel: str, text: str) -> list[RepoChunk]:
    """Structured YAML chunker (DP-3).

    For GitHub Actions workflows: chunks per job.
    For generic YAML: chunks per top-level key.
    Falls back to single config block for small files.
    """
    lines = text.splitlines()
    is_gha = ".github/workflows" in rel or (
        any(lines[i].strip().startswith("on:") for i in range(min(10, len(lines))))
        and any("jobs:" in line for line in lines[:30])
    )

    if is_gha:
        return _chunk_gha_workflow(repo_sha=repo_sha, rel=rel, text=text, lines=lines)

    keys: list[tuple[str, int]] = []
    for m in _YAML_TOP_KEY_RE.finditer(text):
        keys.append((m.group(1), text[:m.start()].count("\n") + 1))

    if len(keys) <= 1:
        return [
            _make_chunk(
                repo_sha=repo_sha, rel=rel, text=text,
                start=1, end=len(lines) or 1,
                language="yaml", kind=ChunkKind.CONFIG_BLOCK,
                qualified_name=Path(rel).name,
            )
        ]

    chunks: list[RepoChunk] = []
    for i, (name, start_line) in enumerate(keys):
        end_line = keys[i + 1][1] - 1 if i + 1 < len(keys) else len(lines)
        chunks.append(
            _make_chunk(
                repo_sha=repo_sha, rel=rel, text=text,
                start=start_line, end=end_line,
                language="yaml", kind=ChunkKind.CONFIG_BLOCK, qualified_name=name,
            )
        )
    return chunks


def _chunk_gha_workflow(
    *, repo_sha: str, rel: str, text: str, lines: list[str]
) -> list[RepoChunk]:
    """Chunk GitHub Actions workflow by job (DP-3)."""
    jobs_line: int | None = None
    for i, line in enumerate(lines):
        if line.strip() == "jobs:" or line.startswith("jobs:"):
            jobs_line = i + 1
            break

    if jobs_line is None:
        return [
            _make_chunk(
                repo_sha=repo_sha, rel=rel, text=text,
                start=1, end=len(lines) or 1,
                language="yaml", kind=ChunkKind.CONFIG_BLOCK,
                qualified_name=Path(rel).name,
            )
        ]

    chunks: list[RepoChunk] = []
    # Preamble (everything before jobs:)
    if jobs_line > 1:
        chunks.append(
            _make_chunk(
                repo_sha=repo_sha, rel=rel, text=text,
                start=1, end=jobs_line,
                language="yaml", kind=ChunkKind.FILE_PREAMBLE, qualified_name=None,
            )
        )

    # Find jobs within the jobs: block
    jobs_text = "\n".join(lines[jobs_line:])
    job_matches: list[tuple[str, int]] = []
    for m in _GHA_JOB_RE.finditer(jobs_text):
        job_line = jobs_line + jobs_text[:m.start()].count("\n") + 1
        job_matches.append((m.group(1), job_line))

    if not job_matches:
        chunks.append(
            _make_chunk(
                repo_sha=repo_sha, rel=rel, text=text,
                start=jobs_line + 1, end=len(lines),
                language="yaml", kind=ChunkKind.CONFIG_BLOCK, qualified_name="jobs",
            )
        )
        return chunks

    for i, (name, start_line) in enumerate(job_matches):
        end_line = job_matches[i + 1][1] - 1 if i + 1 < len(job_matches) else len(lines)
        chunks.append(
            _make_chunk(
                repo_sha=repo_sha, rel=rel, text=text,
                start=start_line, end=end_line,
                language="yaml", kind=ChunkKind.CONFIG_BLOCK, qualified_name=f"job:{name}",
            )
        )
    return chunks


def _chunk_terraform(*, repo_sha: str, rel: str, text: str) -> list[RepoChunk]:
    """Structured Terraform/HCL chunker (DP-3).

    Chunks per resource/data/module/variable/output block.
    """
    lines = text.splitlines()
    blocks: list[tuple[str, int]] = []
    for m in _TF_BLOCK_RE.finditer(text):
        block_type = m.group(1)
        block_name = m.group(2)
        resource_name = m.group(3)
        if resource_name:
            qname = f"{block_name}.{resource_name}"
        else:
            qname = f"{block_type}.{block_name}"
        line = text[:m.start()].count("\n") + 1
        blocks.append((qname, line))

    if not blocks:
        if len(lines) <= 400:
            return [
                _make_chunk(
                    repo_sha=repo_sha, rel=rel, text=text,
                    start=1, end=len(lines) or 1,
                    language="tf", kind=ChunkKind.CONFIG_BLOCK,
                    qualified_name=Path(rel).name,
                )
            ]
        return _chunk_sliding_windows(repo_sha=repo_sha, rel=rel, text=text, language="tf")

    return _symbols_to_chunks(
        repo_sha=repo_sha, rel=rel, text=text, language="tf", symbols=blocks,
    )


def _chunk_sliding_windows(*, repo_sha: str, rel: str, text: str, language: str) -> list[RepoChunk]:
    lines = text.splitlines()
    if not lines:
        return []
    chunks: list[RepoChunk] = []
    step = max(1, _WINDOW_LINES - _WINDOW_OVERLAP)
    index = 0
    for start in range(0, len(lines), step):
        end = min(len(lines), start + _WINDOW_LINES)
        chunks.append(
            _make_chunk(
                repo_sha=repo_sha,
                rel=rel,
                text=text,
                start=start + 1,
                end=end,
                language=language,
                kind=ChunkKind.WINDOW,
                qualified_name=None,
                window_index=index,
            )
        )
        index += 1
        if end >= len(lines):
            break
    return chunks


def _make_chunk(
    *,
    repo_sha: str,
    rel: str,
    text: str,
    start: int,
    end: int,
    language: str,
    kind: ChunkKind,
    qualified_name: str | None,
    window_index: int | None = None,
) -> RepoChunk:
    lines = text.splitlines()
    span = "\n".join(lines[start - 1 : end])
    content_hash = sha256_hex(span.encode("utf-8"))
    chunk_id = make_chunk_id(
        repo_sha=repo_sha,
        file_path=rel,
        kind=kind,
        qualified_name=qualified_name,
        window_index=window_index,
    )
    return RepoChunk(
        chunk_id=chunk_id,
        repo_sha=repo_sha,
        file_path=rel,
        start_line=start,
        end_line=end,
        language=language,
        kind=kind,
        qualified_name=qualified_name,
        text=span,
        content_hash=content_hash,
        sensitivity=sensitivity_for_path(rel),
        subsystem_tags=subsystem_tags_for_path(rel),
    )


def parse_python_imports(text: str) -> list[str]:
    modules: list[str] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return modules
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                modules.append(node.module)
    return modules


def parse_js_imports(text: str) -> list[str]:
    modules: list[str] = []
    for match in _JS_IMPORT_RE.finditer(text):
        mod = match.group(1) or match.group(2)
        if mod:
            modules.append(mod)
    return modules
