"""Materialize a path scope as an iVisor workspace.

iVisor serves exactly two mounts, a read-only `rootfs` at guest `/` and a
read-write `workspace` at guest `/work`, with no per-path ACLs and no third
mount. So a fine-grained path scope cannot be *described* to iVisor; it has to
be *constructed*, by staging only the permitted files into the run's workspace.
What is not staged is not in the guest's namespace at all, which is why a denied
file surfaces as ENOENT rather than EACCES.

COPY, NEVER LINK. Both alternatives are unsafe here:

* A symlink's target is stored verbatim and resolved guest-side against the
  sentry's mount table, so a link to a host file either dangles or is rejected
  as a containment escape (iVisor gofer.rs:788-791), useless either way.
* A hardlink shares the inode, and `/work` is writable, so a guest write would
  reach through and mutate the original host file, defeating the point.

Run-dir layout, which doubles as a re-runnable artifact:

    <run_root>/<run_id>/
      ivisor.conf     # ivisor --config ivisor.conf run <elf>
      workspace/      # guest /work
        repo/<rel>    # CapabilityLease subtree, repo-relative paths preserved
        scope/<i>/    # TaskScope.allowed_paths subtrees
        task/ out/    # inputs (secrets arrive as files: iVisor injects no env)
      trace.jsonl     # verified verdicts
      result.json     # exit interpretation, summaries, digests
"""
from __future__ import annotations

import hashlib
import os
import shutil
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from agentauth.capabilities.hardening.protected_zones import is_protected_path

# _path_glob_match is private but reused deliberately: it is the segment-aware
# matcher that stops `src/*` from swallowing `src/deep/secret.py`. A second
# implementation here could drift from the one the broker enforces, and the two
# disagreeing is exactly the failure this staging step exists to prevent.
from agentauth.capabilities.scoping.enforcement import (
    _path_glob_match,
    normalize_repo_path,
)

GUEST_WORKSPACE = "/work"
_SKIP_DIRS = {"__pycache__", ".git", ".venv", "node_modules"}


class StagingError(ValueError):
    """A scope that cannot be honestly materialized into a workspace."""


@dataclass(frozen=True)
class StagedFile:
    host_src: Path
    guest_rel: str            # relative to the workspace root, e.g. "repo/a/b.py"
    writable: bool = False

    @property
    def guest_path(self) -> str:
        return f"{GUEST_WORKSPACE}/{self.guest_rel}"


@dataclass(frozen=True)
class StagingPlan:
    """What will be staged, and what was deliberately left out."""

    files: tuple[StagedFile, ...] = ()
    refused: tuple[tuple[str, str], ...] = ()   # (path, reason)

    def refusal_reasons(self) -> dict[str, str]:
        return dict(self.refused)


@dataclass
class StagedWorkspace:
    run_id: str
    run_dir: Path
    workspace: Path
    manifest: dict[str, str] = field(default_factory=dict)  # guest_rel -> sha256
    plan: StagingPlan = field(default_factory=StagingPlan)

    def guest_path(self, host: Path | str) -> str:
        """Host path under the workspace -> the guest path iVisor will report."""
        rel = Path(host).resolve().relative_to(self.workspace.resolve())
        return f"{GUEST_WORKSPACE}/{rel.as_posix()}"

    def host_path(self, guest: str) -> Path:
        """Guest `/work/...` path -> the host path backing it."""
        rel = guest[len(GUEST_WORKSPACE):].lstrip("/") if \
            guest.startswith(GUEST_WORKSPACE) else guest.lstrip("/")
        return self.workspace / rel

    def read_guest_file(self, guest: str) -> str | None:
        path = self.host_path(guest)
        try:
            return path.read_text(errors="replace")
        except OSError:
            return None


def build_staging_plan(*, repo_root: Path | str | None = None,
                       lease=None, scope=None,
                       extra_files: Mapping[str, Path | str] | None = None,
                       protected_patterns: tuple[str, ...] | None = None,
                       ) -> StagingPlan:
    """Decide what to stage from a lease and/or a task scope.

    Fail-closed rules:

    * A lease path that is absolute or contains `..` is a malformed grant and
      raises, rather than being silently dropped.
    * A path in a protected zone or matched by `scope.denied_paths` is refused.
      If it was named *explicitly* in the lease, that contradiction raises: a
      signed grant that names a file the deny-list forbids is a configuration
      bug, and papering over it would let the two policies disagree silently.
    """
    files: list[StagedFile] = []
    refused: list[tuple[str, str]] = []
    denied = tuple(getattr(scope, "denied_paths", ()) or ())
    allow_exceptions = set(getattr(lease, "explicit_allow_resources", ()) or ())
    protect_kwargs = {"allow_exceptions": allow_exceptions}
    if protected_patterns is not None:
        protect_kwargs["patterns"] = protected_patterns

    def _refuse(path: str, reason: str, *, explicit: bool) -> None:
        if explicit:
            raise StagingError(
                f"{path!r} is named by the grant but {reason}; refusing to stage "
                "it. Resolve the contradiction in the grant rather than here.")
        refused.append((path, reason))

    if lease is not None:
        if repo_root is None:
            raise StagingError("staging a CapabilityLease needs repo_root")
        root = Path(repo_root)
        write_files = set(getattr(lease, "write_files", ()) or ())
        for raw in sorted(set(getattr(lease, "read_files", ()) or ()) | write_files):
            normalized = normalize_repo_path(raw)
            if normalized is None:
                raise StagingError(
                    f"lease path {raw!r} is absolute or escapes the repo root; "
                    "CapabilityLease paths are repo-relative by contract")
            if is_protected_path(normalized, **protect_kwargs):
                _refuse(normalized, "protected-zone", explicit=True)
                continue
            if _matches_any(normalized, denied):
                _refuse(normalized, "denied-path", explicit=True)
                continue
            source = root / normalized
            if not source.is_file():
                refused.append((normalized, "missing"))
                continue
            files.append(StagedFile(host_src=source,
                                    guest_rel=f"repo/{normalized}",
                                    writable=raw in write_files))

    for index, allowed in enumerate(getattr(scope, "allowed_paths", ()) or ()):
        base = Path(allowed)
        if not base.exists():
            refused.append((str(base), "missing"))
            continue
        prefix = f"scope/{index}"
        for source, rel in _walk(base):
            if is_protected_path(rel, **protect_kwargs):
                _refuse(rel, "protected-zone", explicit=False)
                continue
            if _matches_any(rel, denied) or _matches_any(str(source), denied):
                _refuse(str(source), "denied-path", explicit=False)
                continue
            files.append(StagedFile(host_src=source,
                                    guest_rel=f"{prefix}/{rel}", writable=True))

    for guest_rel, source in (extra_files or {}).items():
        files.append(StagedFile(host_src=Path(source),
                                guest_rel=guest_rel.lstrip("/"), writable=True))

    return StagingPlan(files=tuple(files), refused=tuple(refused))


def stage_workspace(plan: StagingPlan, run_root: Path | str, *,
                    run_id: str | None = None,
                    reuse: Path | None = None) -> StagedWorkspace:
    """Create the run dir and copy the planned files into its workspace."""
    run_id = run_id or uuid.uuid4().hex[:12]
    run_dir = Path(reuse) if reuse is not None else Path(run_root) / run_id
    workspace = run_dir / "workspace"
    for sub in ("", "task", "out"):
        (workspace / sub).mkdir(parents=True, exist_ok=True)

    manifest: dict[str, str] = {}
    for item in plan.files:
        target = workspace / item.guest_rel
        target.parent.mkdir(parents=True, exist_ok=True)
        # Re-staging into a reused run dir has to replace a previously staged
        # file, which may have been chmod'd read-only below, and copying onto
        # a 0o444 file fails. Unlinking also drops any guest edit, which is the
        # point: staged inputs are restored to the pristine host copy each run.
        if target.exists() or target.is_symlink():
            target.unlink()
        shutil.copyfile(item.host_src, target)   # copyfile: never follows into a link target
        if not item.writable:
            # A soft belt only: /work is writable by construction, so read-only
            # intent is really enforced above iVisor by restricting write-back.
            os.chmod(target, 0o444)
        manifest[item.guest_rel] = _digest_file(target)
    return StagedWorkspace(run_id=run_id, run_dir=run_dir, workspace=workspace,
                           manifest=manifest, plan=plan)


def workspace_delta(staged: StagedWorkspace) -> dict:
    """What the guest changed: new, modified, and deleted files."""
    created, modified, deleted = [], [], []
    seen: set[str] = set()
    for path in sorted(staged.workspace.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(staged.workspace).as_posix()
        seen.add(rel)
        before = staged.manifest.get(rel)
        if before is None:
            created.append(rel)
        elif before != _digest_file(path):
            modified.append(rel)
    deleted = sorted(set(staged.manifest) - seen)
    return {"created": created, "modified": modified, "deleted": deleted}


def collect_writeback(staged: StagedWorkspace, lease) -> dict[str, bytes]:
    """Guest-side changes the lease actually authorizes writing back.

    Returned for the caller to apply, never applied here. Anything the guest
    changed outside `lease.write_files` is dropped, which is what keeps a
    writable `/work` from laundering an out-of-scope edit back into the repo.
    """
    if lease is None:
        return {}
    allowed = {normalize_repo_path(p) for p in getattr(lease, "write_files", ()) or ()}
    allowed.discard(None)
    out: dict[str, bytes] = {}
    delta = workspace_delta(staged)
    for rel in delta["created"] + delta["modified"]:
        if not rel.startswith("repo/"):
            continue
        repo_rel = rel[len("repo/"):]
        if repo_rel in allowed or any(
                _path_glob_match(repo_rel, pattern) for pattern in allowed):
            out[repo_rel] = (staged.workspace / rel).read_bytes()
    return out


def _walk(base: Path) -> Iterable[tuple[Path, str]]:
    """Yield (source, relative-path) for every regular file under `base`.

    Symlinks are skipped entirely rather than followed: copying through one
    would smuggle a file from outside the scope into the workspace under an
    in-scope name.
    """
    if base.is_file():
        yield base, base.name
        return
    for root, dirs, names in os.walk(base, followlinks=False):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS
                   and not os.path.islink(os.path.join(root, d))]
        for name in sorted(names):
            source = Path(root) / name
            if source.is_symlink() or not source.is_file():
                continue
            yield source, source.relative_to(base).as_posix()


def _matches_any(path: str, patterns: Iterable[str]) -> bool:
    normalized = path.lstrip("/")
    for pattern in patterns:
        cleaned = str(pattern).lstrip("/")
        if not cleaned:
            continue
        if _path_glob_match(normalized, cleaned) or normalized.startswith(
                cleaned.rstrip("*").rstrip("/") + "/"):
            return True
        if normalized == cleaned:
            return True
    return False


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()
