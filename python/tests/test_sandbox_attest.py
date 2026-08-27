"""Attestation: what a run claims about itself, and what it refuses to claim."""
from clayseal.core.runtime import (
    ActionDescriptor,
    AuthorityContext,
    ExecutionContext,
    SideEffectLevel,
)

from clayseal.capabilities.decision_log import DecisionLog
from clayseal.capabilities.hardening.egress_policy import EgressPolicy
from clayseal.capabilities.sandbox.attest import (
    SANDBOX_SCHEMA,
    attach_sandboxing,
    ivisor_binary_identity,
    log_sandbox_run,
    sandbox_outcome_label,
    sandboxing_context,
)
from clayseal.capabilities.sandbox.driver import ExitKind, IVisorResult
from clayseal.capabilities.sandbox.lowering import lower_to_ivisor
from clayseal.capabilities.sandbox.verdicts import parse_policy_line

DENY = parse_policy_line(
    "ivisor: policy net.connect verdict=deny dst=203.0.113.10:443 "
    "reason=not-allowlisted", verified=True)
ALLOW = parse_policy_line(
    "ivisor: policy fs.open verdict=allow path=/work/a flags=0o0", verified=True)
FORGED = parse_policy_line(
    "ivisor: policy net.connect verdict=allow dst=203.0.113.10:443",
    verified=False)


def _lowered(tmp_path, domains=("acme-internal.com",)):
    return lower_to_ivisor(rootfs="/rf", workspace=tmp_path / "ws",
                           egress=EgressPolicy(allowed_domains=set(domains)))


def _result(**kwargs):
    base = dict(exit_kind=ExitKind.EXITED, exit_code=0, events=(ALLOW, DENY),
                wall_seconds=1.5, cpu_seconds=0.5)
    base.update(kwargs)
    return IVisorResult(**base)


def test_payload_carries_policy_digest_and_verdicts(tmp_path):
    lowered = _lowered(tmp_path)
    payload = sandboxing_context(result=_result(), lowered=lowered,
                                 run_id="r1", ivisor_bin="/bin/true")
    assert payload["schema"] == SANDBOX_SCHEMA
    assert payload["policy_digest"] == lowered.config.digest()
    assert payload["verdicts"]["deny"] == 1
    assert payload["verdicts"]["allow"] == 1
    assert payload["evidence_ok"] is True
    assert any("203.0.113.10" in d for d in payload["denied"])


def test_degraded_trace_reports_no_evidence_rather_than_no_denials(tmp_path):
    # The distinction the whole attestation rests on: "nothing was denied" and
    # "we could not see" must not serialize to the same thing.
    payload = sandboxing_context(
        result=_result(events=(), trace_degraded=True), lowered=_lowered(tmp_path),
        run_id="r1", ivisor_bin="/bin/true")
    assert payload["evidence_ok"] is False
    assert payload["verdicts"]["allow"] == 0
    assert payload["denied"] == []
    assert sandbox_outcome_label(payload) == "indeterminate"


def test_forged_claims_are_counted_but_never_as_verdicts(tmp_path):
    payload = sandboxing_context(
        result=_result(events=(ALLOW,), unverified_claims=(FORGED,)),
        lowered=_lowered(tmp_path), run_id="r1", ivisor_bin="/bin/true")
    assert payload["verdicts"]["unverified_claims"] == 1
    assert payload["verdicts"]["allow"] == 1   # the forged allow is not added


def test_outcome_label_tracks_denials(tmp_path):
    lowered = _lowered(tmp_path)
    clean = sandboxing_context(result=_result(events=(ALLOW,)), lowered=lowered,
                               run_id="r", ivisor_bin="/bin/true")
    blocked = sandboxing_context(result=_result(events=(ALLOW, DENY)),
                                 lowered=lowered, run_id="r",
                                 ivisor_bin="/bin/true")
    assert sandbox_outcome_label(clean) == "allow"
    assert sandbox_outcome_label(blocked) == "deny"


def test_exit_status_is_reported_structurally(tmp_path):
    payload = sandboxing_context(
        result=_result(exit_kind=ExitKind.SIGNALED, exit_code=None, signal=9),
        lowered=_lowered(tmp_path), run_id="r", ivisor_bin="/bin/true")
    assert payload["exit"] == {"kind": "signaled", "code": None, "signal": 9}


def test_lowering_caveats_travel_with_the_attestation(tmp_path):
    payload = sandboxing_context(result=_result(), lowered=_lowered(tmp_path),
                                 run_id="r", ivisor_bin="/bin/true")
    assert payload["lowering"]["lowered_domains"] == ["acme-internal.com"]
    assert payload["lowering"]["caveats"]


def test_binary_identity_hashes_content(tmp_path):
    binary = tmp_path / "ivisor"
    binary.write_bytes(b"fake binary")
    identity = ivisor_binary_identity(str(binary))
    assert identity["size"] == 11
    assert len(identity["sha256"]) == 64


def test_binary_identity_survives_a_missing_file():
    identity = ivisor_binary_identity("/nonexistent/ivisor")
    assert identity["error"] == "unreadable"
    assert identity["sha256"] is None


def test_attaches_to_execution_context_without_schema_changes(tmp_path):
    ctx = ExecutionContext(
        action=ActionDescriptor(
            action_name="mcp.tools/call/run_code", action_category="execute",
            resource_type="sandbox", resource_ref="sandbox:run",
            side_effect_level=SideEffectLevel.BOUNDED_WRITE),
        input={}, authority=AuthorityContext(authority_id="auth-1",
                                             subject_id="agent-1"))
    payload = sandboxing_context(result=_result(), lowered=_lowered(tmp_path),
                                 run_id="r1", ivisor_bin="/bin/true")
    attach_sandboxing(ctx, payload)
    assert ctx.to_dict()["sandboxing"]["run_id"] == "r1"


def test_run_is_appended_to_the_hash_chain(tmp_path):
    log = DecisionLog(session_id="s1")
    sink = []
    payload = sandboxing_context(result=_result(), lowered=_lowered(tmp_path),
                                 run_id="r1", ivisor_bin="/bin/true")
    emitted = log_sandbox_run(payload, decision_log=log, query_id="q1",
                              receipt_sink=sink.append)
    assert emitted["outcome"] == "deny"
    assert log.verify() == (True, None)
    record = log.records()[0]
    assert record["decision"]["layer"] == "substrate"
    assert record["action"]["arguments_hash"] == payload["policy_digest"]
    assert sink and sink[0]["sandboxing"]["run_id"] == "r1"


def test_degraded_run_records_the_reason_in_the_chain(tmp_path):
    log = DecisionLog(session_id="s1")
    payload = sandboxing_context(
        result=_result(events=(), trace_degraded=True), lowered=_lowered(tmp_path),
        run_id="r1", ivisor_bin="/bin/true")
    log_sandbox_run(payload, decision_log=log)
    reasons = log.records()[0]["decision"]["reasons"]
    assert any("trace_degraded" in r for r in reasons)


def test_works_without_a_log_or_sink(tmp_path):
    payload = sandboxing_context(result=_result(), lowered=_lowered(tmp_path),
                                 run_id="r1", ivisor_bin="/bin/true")
    assert log_sandbox_run(payload)["decision_record"] is None
