"""Workspace staging: what reaches the guest namespace, and what cannot."""
import os

import pytest

from clayseal.capabilities.sandbox.staging import (
    GUEST_WORKSPACE,
    StagingError,
    build_staging_plan,
    collect_writeback,
    stage_workspace,
    workspace_delta,
)
from clayseal.capabilities.scoping.models import CapabilityLease
from clayseal.core.task_scope import TaskScope


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "secrets").mkdir()
    (root / "src" / "a.py").write_text("print('a')\n")
    (root / "src" / "b.py").write_text("print('b')\n")
    (root / "secrets" / "prod.env").write_text("TOKEN=hunter2\n")
    return root


def _lease(read=(), write=()):
    return CapabilityLease(query_id="q1", repo_sha="deadbeef", seed_chunk_ids=[],
                           read_files=set(read), write_files=set(write))


def test_stages_only_the_leased_files(repo, tmp_path):
    plan = build_staging_plan(repo_root=repo,
                              lease=_lease(read=["src/a.py"]))
    staged = stage_workspace(plan, tmp_path / "runs")
    assert (staged.workspace / "repo/src/a.py").read_text() == "print('a')\n"
    # b.py was never leased, so it is not in the guest namespace at all.
    assert not (staged.workspace / "repo/src/b.py").exists()


def test_staged_files_are_copies_not_links(repo, tmp_path):
    plan = build_staging_plan(repo_root=repo, lease=_lease(read=["src/a.py"]))
    staged = stage_workspace(plan, tmp_path / "runs")
    target = staged.workspace / "repo/src/a.py"
    assert not target.is_symlink()
    assert target.stat().st_nlink == 1
    assert target.stat().st_ino != (repo / "src/a.py").stat().st_ino
    # A guest write must not reach the original.
    os.chmod(target, 0o644)
    target.write_text("tampered\n")
    assert (repo / "src/a.py").read_text() == "print('a')\n"


def test_protected_zone_file_swept_up_by_a_scope_is_refused(repo, tmp_path):
    scope = TaskScope(allowed_paths=[str(repo)])
    plan = build_staging_plan(scope=scope)
    reasons = plan.refusal_reasons()
    assert any("prod.env" in path for path in reasons)
    assert reasons[next(p for p in reasons if "prod.env" in p)] == "protected-zone"
    staged = stage_workspace(plan, tmp_path / "runs")
    assert not list(staged.workspace.rglob("prod.env"))


def test_lease_naming_a_protected_file_is_a_hard_error(repo):
    # A signed grant that contradicts the deny-list is a config bug; staging it
    # silently would let the two policies disagree without anyone noticing.
    with pytest.raises(StagingError, match="protected-zone"):
        build_staging_plan(repo_root=repo,
                           lease=_lease(read=["secrets/prod.env"]))


def test_denied_path_is_refused(repo, tmp_path):
    scope = TaskScope(allowed_paths=[str(repo)], denied_paths=["src/b.py"])
    plan = build_staging_plan(scope=scope)
    staged = stage_workspace(plan, tmp_path / "runs")
    assert not list(staged.workspace.rglob("b.py"))
    assert list(staged.workspace.rglob("a.py"))


@pytest.mark.parametrize("bad", ["/etc/passwd", "../../etc/passwd", "a/../../b"])
def test_absolute_or_traversing_lease_paths_raise(repo, bad):
    with pytest.raises(StagingError, match="repo-relative"):
        build_staging_plan(repo_root=repo, lease=_lease(read=[bad]))


def test_missing_lease_file_is_recorded_not_fatal(repo):
    plan = build_staging_plan(repo_root=repo, lease=_lease(read=["src/gone.py"]))
    assert ("src/gone.py", "missing") in plan.refused
    assert plan.files == ()


def test_symlinks_in_a_scope_are_not_followed(repo, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n")
    (repo / "src" / "link.txt").symlink_to(outside)
    plan = build_staging_plan(scope=TaskScope(allowed_paths=[str(repo)]))
    staged = stage_workspace(plan, tmp_path / "runs")
    assert not list(staged.workspace.rglob("link.txt"))


def test_guest_and_host_paths_round_trip(repo, tmp_path):
    plan = build_staging_plan(repo_root=repo, lease=_lease(read=["src/a.py"]))
    staged = stage_workspace(plan, tmp_path / "runs")
    host = staged.workspace / "repo/src/a.py"
    guest = staged.guest_path(host)
    assert guest == f"{GUEST_WORKSPACE}/repo/src/a.py"
    assert staged.host_path(guest) == host


def test_workspace_delta_reports_guest_changes(repo, tmp_path):
    plan = build_staging_plan(repo_root=repo,
                              lease=_lease(read=["src/a.py"], write=["src/b.py"]))
    staged = stage_workspace(plan, tmp_path / "runs")
    (staged.workspace / "out" / "new.txt").write_text("fresh\n")
    target = staged.workspace / "repo/src/b.py"
    os.chmod(target, 0o644)
    target.write_text("changed\n")
    (staged.workspace / "repo/src/a.py").unlink()

    delta = workspace_delta(staged)
    assert "out/new.txt" in delta["created"]
    assert "repo/src/b.py" in delta["modified"]
    assert "repo/src/a.py" in delta["deleted"]


def test_writeback_is_restricted_to_the_lease_write_set(repo, tmp_path):
    lease = _lease(read=["src/a.py"], write=["src/b.py"])
    plan = build_staging_plan(repo_root=repo, lease=lease)
    staged = stage_workspace(plan, tmp_path / "runs")

    for name in ("a.py", "b.py"):
        target = staged.workspace / f"repo/src/{name}"
        os.chmod(target, 0o644)
        target.write_text(f"guest wrote {name}\n")

    back = collect_writeback(staged, lease)
    # b.py is writable; a.py was read-only, so a guest edit is dropped rather
    # than laundered back into the repo.
    assert set(back) == {"src/b.py"}


def test_read_only_files_are_chmodded_as_a_soft_belt(repo, tmp_path):
    plan = build_staging_plan(repo_root=repo, lease=_lease(read=["src/a.py"]))
    staged = stage_workspace(plan, tmp_path / "runs")
    mode = (staged.workspace / "repo/src/a.py").stat().st_mode
    assert not mode & 0o222


def test_restaging_into_a_reused_run_dir_replaces_read_only_files(repo, tmp_path):
    # The per-tool-call episode model reuses one run dir across many spawns, so
    # re-staging must not trip over the chmod applied to read-only lease files.
    plan = build_staging_plan(repo_root=repo, lease=_lease(read=["src/a.py"]))
    first = stage_workspace(plan, tmp_path / "runs", run_id="r1")
    target = first.workspace / "repo/src/a.py"

    os.chmod(target, 0o644)
    target.write_text("guest tampered\n")

    second = stage_workspace(plan, tmp_path / "runs", run_id="r1",
                             reuse=first.run_dir)
    # Staged inputs are restored to the pristine host copy on each run.
    assert (second.workspace / "repo/src/a.py").read_text() == "print('a')\n"


def test_restaging_preserves_guest_created_files(repo, tmp_path):
    plan = build_staging_plan(repo_root=repo, lease=_lease(read=["src/a.py"]))
    first = stage_workspace(plan, tmp_path / "runs", run_id="r1")
    (first.workspace / "out" / "report.txt").write_text("episode state\n")

    second = stage_workspace(plan, tmp_path / "runs", run_id="r1",
                             reuse=first.run_dir)
    assert (second.workspace / "out" / "report.txt").read_text() == "episode state\n"


def test_extra_files_land_where_asked(repo, tmp_path):
    source = tmp_path / "task.json"
    source.write_text("{}")
    plan = build_staging_plan(extra_files={"task/task.json": source})
    staged = stage_workspace(plan, tmp_path / "runs")
    assert (staged.workspace / "task/task.json").read_text() == "{}"


def test_lease_without_repo_root_is_refused(repo):
    with pytest.raises(StagingError, match="repo_root"):
        build_staging_plan(lease=_lease(read=["src/a.py"]))
