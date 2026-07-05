from __future__ import annotations

from dataclasses import dataclass, field

from agentauth.capabilities.scoping._bfs import expand_frontier
from agentauth.capabilities.scoping.imports_graph import is_build_manifest
from agentauth.capabilities.scoping.models import SensitivityLabel


@dataclass
class ClosurePolicy:
    read_import_depth: int = 1
    write_import_depth: int = 1
    max_read_files: int = 200
    max_write_dep_files: int = 24
    allow_read_on_protected: bool = True
    allow_write_on_protected: bool = False


@dataclass
class FileClosure:
    seed_files: set[str] = field(default_factory=set)
    read_files: set[str] = field(default_factory=set)
    write_files: set[str] = field(default_factory=set)
    build_manifest_files: set[str] = field(default_factory=set)
    blocked_protected: set[str] = field(default_factory=set)


def compute_file_closure(
    *,
    seed_files: set[str],
    import_edges: list[tuple[str, str]],
    build_manifest_files: set[str],
    file_sensitivity: dict[str, SensitivityLabel],
    explicit_allow_files: set[str],
    policy: ClosurePolicy | None = None,
) -> FileClosure:
    cfg = policy or ClosurePolicy()
    seeds = {path.replace("\\", "/") for path in seed_files if path}
    write_seeds = {
        path
        for path in seeds
        if file_sensitivity.get(path, SensitivityLabel.NORMAL) == SensitivityLabel.NORMAL
        or path in explicit_allow_files
    }
    read_set = expand_frontier(
        seeds,
        edges=import_edges,
        depth=cfg.read_import_depth,
        cap=cfg.max_read_files,
    )
    write_deps = expand_frontier(
        write_seeds,
        edges=import_edges,
        depth=cfg.write_import_depth,
        cap=cfg.max_write_dep_files + len(write_seeds),
    )
    write_set = set(write_seeds)
    for path in write_deps:
        if path in seeds:
            continue
        label = file_sensitivity.get(path, SensitivityLabel.NORMAL)
        if label != SensitivityLabel.NORMAL and path not in explicit_allow_files:
            continue
        if len(write_set) - len(write_seeds) >= cfg.max_write_dep_files:
            break
        write_set.add(path)

    manifests = {path for path in build_manifest_files if is_build_manifest(path)}
    read_set |= manifests

    blocked: set[str] = set()
    for path in list(read_set):
        label = file_sensitivity.get(path, SensitivityLabel.NORMAL)
        if label == SensitivityLabel.NORMAL or path in explicit_allow_files:
            continue
        if not cfg.allow_read_on_protected:
            read_set.discard(path)
            blocked.add(path)
    for path in list(write_set):
        label = file_sensitivity.get(path, SensitivityLabel.NORMAL)
        if label == SensitivityLabel.NORMAL or path in explicit_allow_files:
            continue
        if not cfg.allow_write_on_protected:
            write_set.discard(path)
            blocked.add(path)

    return FileClosure(
        seed_files=seeds,
        read_files=read_set,
        write_files=write_set,
        build_manifest_files=manifests,
        blocked_protected=blocked,
    )
