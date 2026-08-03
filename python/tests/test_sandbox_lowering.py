"""Envelope -> iVisor policy lowering, and the boundary it must not cross."""
import pytest
from agentauth.core.task_scope import TaskScope

from agentauth.capabilities.hardening.egress_policy import EgressPolicy
from agentauth.capabilities.sandbox.lowering import LoweringError, lower_to_ivisor
from agentauth.capabilities.scoping.models import CapabilityLease


def _lower(tmp_path, **kwargs):
    kwargs.setdefault("rootfs", "/rootfs")
    kwargs.setdefault("workspace", tmp_path / "ws")
    return lower_to_ivisor(**kwargs)


def test_allowed_domains_lower_to_the_allow_list(tmp_path):
    egress = EgressPolicy(allowed_domains={"acme-internal.com", "api.acme.com"})
    lowered = _lower(tmp_path, egress=egress)
    assert lowered.config.allow == ("acme-internal.com", "api.acme.com")
    assert "allow = acme-internal.com,api.acme.com" in lowered.config.render()


def test_no_egress_means_deny_all(tmp_path):
    lowered = _lower(tmp_path)
    assert lowered.config.allow == ()
    assert "allow" not in lowered.config.render()


def test_ports_are_stripped_with_a_recorded_caveat(tmp_path):
    # iVisor parses a port here but never enforces it; keeping it would imply
    # precision the substrate does not have.
    egress = EgressPolicy(allowed_domains={"api.acme.com:443"})
    lowered = _lower(tmp_path, egress=egress)
    assert lowered.config.allow == ("api.acme.com",)
    assert any("does not enforce it" in c for c in lowered.report.caveats)


def test_subdomain_suffix_narrowing_is_recorded(tmp_path):
    egress = EgressPolicy(allowed_domains={"acme.com"})
    lowered = _lower(tmp_path, egress=egress)
    assert any("strictly tighter" in c for c in lowered.report.caveats)


def test_recipients_never_lower(tmp_path):
    # The layer boundary: a syscall gate has no vocabulary for an IBAN.
    egress = EgressPolicy(allowed_domains={"bank.example.com"},
                          allowed_recipients={"GB123"}, bind_recipients=True)
    lowered = _lower(tmp_path, egress=egress)
    rendered = lowered.config.render()
    assert "GB123" not in rendered
    assert "recipient binding" in lowered.report.retained_above


def test_budgets_and_tool_scope_are_retained_above(tmp_path):
    lowered = _lower(tmp_path)
    assert "value/call budgets" in lowered.report.retained_above
    assert "tool scope" in lowered.report.retained_above
    assert "argument binding" in lowered.report.retained_above


def test_allow_all_is_refused_rather_than_silently_denied(tmp_path):
    # Lowering allow_all to deny-all would be safe but would break the workload
    # with no explanation; there is no wildcard to widen with either.
    with pytest.raises(LoweringError, match="allow_all"):
        _lower(tmp_path, egress=EgressPolicy(allow_all=True))


def test_unparseable_domain_fails_closed(tmp_path):
    # iVisor would warn and skip this, silently narrowing egress.
    with pytest.raises(LoweringError):
        _lower(tmp_path, egress=EgressPolicy(allowed_domains={"*.evil.com"}))


def test_lease_files_are_planned_for_staging(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.py").write_text("x\n")
    lease = CapabilityLease(query_id="q", repo_sha="s", seed_chunk_ids=[],
                            read_files={"src/a.py"})
    lowered = _lower(tmp_path, lease=lease, repo_root=repo)
    assert [f.guest_rel for f in lowered.staging.files] == ["repo/src/a.py"]


def test_denied_paths_are_retained_above_since_they_cannot_lower(tmp_path):
    scope = TaskScope(allowed_paths=[str(tmp_path)], denied_paths=["secret/**"])
    lowered = _lower(tmp_path, scope=scope)
    assert any("denied_paths" in item for item in lowered.report.retained_above)


def test_direct_mode_mounts_the_single_allowed_path(tmp_path):
    target = tmp_path / "only"
    target.mkdir()
    scope = TaskScope(allowed_paths=[str(target)])
    lowered = _lower(tmp_path, scope=scope, workspace_mode="direct")
    assert lowered.config.workspace == str(target)
    assert any("mounted directly" in c for c in lowered.report.caveats)


def test_direct_mode_refuses_multiple_paths(tmp_path):
    scope = TaskScope(allowed_paths=[str(tmp_path / "a"), str(tmp_path / "b")])
    with pytest.raises(LoweringError, match="exactly one allowed path"):
        _lower(tmp_path, scope=scope, workspace_mode="direct")


def test_direct_mode_refuses_denied_paths(tmp_path):
    # Mounting the directory would put the denied files in the namespace.
    scope = TaskScope(allowed_paths=[str(tmp_path)], denied_paths=["x/**"])
    with pytest.raises(LoweringError, match="cannot honor denied_paths"):
        _lower(tmp_path, scope=scope, workspace_mode="direct")


def test_unknown_workspace_mode_is_refused(tmp_path):
    with pytest.raises(LoweringError, match="workspace_mode"):
        _lower(tmp_path, workspace_mode="bogus")


def test_extra_allow_entries_are_validated_too(tmp_path):
    with pytest.raises(LoweringError):
        _lower(tmp_path, extra_allow=["not a host"])
    ok = _lower(tmp_path, extra_allow=["pypi.org"])
    assert ok.config.allow == ("pypi.org",)


def test_report_serializes(tmp_path):
    lowered = _lower(tmp_path, egress=EgressPolicy(allowed_domains={"a.com"}))
    payload = lowered.report.to_dict()
    assert payload["lowered_domains"] == ["a.com"]
    assert isinstance(payload["caveats"], list)
