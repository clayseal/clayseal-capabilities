from __future__ import annotations

from pathlib import Path

from agentauth.capabilities.scoping.chunkers import parse_js_imports, parse_python_imports

_BUILD_MANIFEST_NAMES = frozenset(
    {
        "pyproject.toml",
        "package.json",
        "package-lock.json",
        "Cargo.toml",
        "go.mod",
        "setup.py",
        "setup.cfg",
    }
)


def is_build_manifest(file_path: str) -> bool:
    return Path(file_path).name in _BUILD_MANIFEST_NAMES


def resolve_import_to_repo_path(module: str, *, repo_root: Path, source_file: Path) -> str | None:
    """Best-effort same-repo import target (v1 heuristic)."""
    module = module.strip().strip('"').strip("'")
    if not module or module.startswith("."):
        return None
    root = repo_root.resolve()
    candidate = (root / module.replace(".", "/")).resolve()
    if not str(candidate).startswith(str(root)):
        return None

    if candidate.is_file():
        return candidate.relative_to(repo_root).as_posix()
    for suffix in (".py", ".ts", ".tsx", ".js", ".jsx", "/__init__.py"):
        probe = Path(str(candidate) + suffix) if not suffix.startswith("/") else candidate / suffix.lstrip("/")
        if probe.is_file():
            return probe.relative_to(repo_root).as_posix()
    if candidate.is_dir() and (candidate / "__init__.py").is_file():
        return (candidate / "__init__.py").relative_to(repo_root).as_posix()
    return None


def extract_import_edges(
    *,
    repo_root: Path,
    file_paths: list[str],
    file_text: dict[str, str],
) -> list[tuple[str, str]]:
    edges: list[tuple[str, str]] = []
    root = repo_root.resolve()
    for rel in file_paths:
        text = file_text.get(rel, "")
        source = root / rel
        suffix = source.suffix.lower()
        if suffix == ".py":
            modules = parse_python_imports(text)
        elif suffix in {".ts", ".tsx", ".js", ".jsx"}:
            modules = parse_js_imports(text)
        else:
            continue
        for module in modules:
            target = resolve_import_to_repo_path(module, repo_root=root, source_file=source)
            if target and target != rel:
                edges.append((rel, target))
    return edges
