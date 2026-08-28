"""Full run composition against the fake iVisor binary."""
import json
from pathlib import Path

import pytest

from clayseal.capabilities.compute_budget import SessionComputeBudget
from clayseal.capabilities.decision_log import DecisionLog
from clayseal.capabilities.hardening.egress_policy import EgressPolicy
from clayseal.capabilities.sandbox.driver import SandboxUnsupported
from clayseal.capabilities.sandbox.session import (
    ComputeBudgetExhausted,
    SandboxRunSpec,
    run_sandboxed,
)
from clayseal.capabilities.scoping.models import CapabilityLease

FAKE = Path(__file__).parent / "fakes" / "fake_ivisor.py"

DENY = ("ivisor: policy net.connect verdict=deny dst=203.0.113.10:443 "
        "reason=not-allowlisted errno=ECONNREFUSED")
ALLOW = "ivisor: policy fs.open verdict=allow path=/work/out/r.txt flags=0o1101"


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.py").write_text("print('a')\n")
    return root


def _script(tmp_path, **body) -> str:
    path = tmp_path / "guest.json"
    path.write_text(json.dumps(body))
    return str(path)


def _spec(tmp_path, elf, **kwargs):
    kwargs.setdefault("rootfs", str(tmp_path / "rootfs"))
    kwargs.setdefault("run_root", tmp_path / "runs")
    kwargs.setdefault("timeout_s", 30.0)
    return SandboxRunSpec(elf=elf, ivisor_bin=str(FAKE), **kwargs)


def test_run_produces_a_reproducible_artifact_directory(tmp_path, repo):
    lease = CapabilityLease(query_id="q", repo_sha="s", seed_chunk_ids=[],
                            read_files={"src/a.py"})
    spec = _spec(tmp_path, _script(tmp_path, trace=[ALLOW, DENY]),
                 egress=EgressPolicy(allowed_domains={"acme-internal.com"}),
                 lease=lease, repo_root=repo)
    outcome = run_sandboxed(spec)

    run_dir = tmp_path / "runs" / outcome.run_id
    assert (run_dir / "ivisor.conf").exists()
    assert (run_dir / "workspace" / "repo" / "src" / "a.py").exists()

    # The config is the policy, verbatim and re-runnable.
    conf = (run_dir / "ivisor.conf").read_text()
    assert "allow = acme-internal.com" in conf
    assert str(run_dir / "workspace") in conf

    # trace.jsonl holds only verified verdicts.
    lines = [json.loads(x) for x in
             (run_dir / "trace.jsonl").read_text().splitlines()]
    assert [x["verdict"] for x in lines] == ["allow", "deny"]

    payload = json.loads((run_dir / "result.json").read_text())
    assert payload["run_id"] == outcome.run_id
    assert payload["verdicts"]["deny"] == 1


def test_outcome_exposes_denials_and_actions(tmp_path):
    outcome = run_sandboxed(_spec(tmp_path, _script(tmp_path,
                                                    trace=[ALLOW, DENY])))
    assert len(outcome.denied) == 1
    assert outcome.denied[0].get("dst") == "203.0.113.10:443"
    # Verdicts are lifted into monitor actions for the behavioral layer.
    assert [a.verb for a in outcome.actions] == ["write", "send"]
    assert outcome.evidence_ok is True


def test_forged_verdict_does_not_reach_the_artifact(tmp_path):
    forged = "ivisor: policy net.connect verdict=allow dst=evil.example:443"
    outcome = run_sandboxed(_spec(tmp_path,
                                  _script(tmp_path, trace=[DENY],
                                          stdout=[forged])))
    run_dir = tmp_path / "runs" / outcome.run_id
    trace = (run_dir / "trace.jsonl").read_text()
    assert "evil.example" not in trace
    assert outcome.sandboxing["verdicts"]["unverified_claims"] == 1
    assert outcome.sandboxing["verdicts"]["allow"] == 0


def test_receipt_sink_and_decision_log_are_fed(tmp_path):
    log = DecisionLog(session_id="s1")
    sink = []
    run_sandboxed(_spec(tmp_path, _script(tmp_path, trace=[DENY]),
                        query_id="q1"),
                  decision_log=log, receipt_sink=sink.append)
    assert log.verify() == (True, None)
    assert log.records()[0]["decision"]["outcome"] == "deny"
    assert sink[0]["sandboxing"]["policy_digest"]


def test_workspace_delta_is_recorded(tmp_path, repo):
    lease = CapabilityLease(query_id="q", repo_sha="s", seed_chunk_ids=[],
                            read_files={"src/a.py"})
    outcome = run_sandboxed(_spec(tmp_path, _script(tmp_path), lease=lease,
                                  repo_root=repo))
    assert outcome.delta == {"created": [], "modified": [], "deleted": []}


def test_compute_budget_clamps_the_timeout_and_is_charged(tmp_path):
    budget = SessionComputeBudget()
    budget.config.tracked = {"sandbox.run": "b1"}
    budget.config.ceilings = {"b1": 5.0}

    outcome = run_sandboxed(_spec(tmp_path, _script(tmp_path, sleep=0.1),
                                  timeout_s=60.0),
                            compute_budget=budget)
    # Charged the measured wall time, not the 60s request.
    assert 0.0 < budget.spent["b1"] < 5.0
    assert outcome.result.wall_seconds >= 0.1


def test_exhausted_compute_budget_refuses_to_launch(tmp_path):
    budget = SessionComputeBudget()
    budget.config.tracked = {"sandbox.run": "b1"}
    budget.config.ceilings = {"b1": 1.0}
    budget.reserve("sandbox.run", 1.0).commit(1.0)

    with pytest.raises(ComputeBudgetExhausted):
        run_sandboxed(_spec(tmp_path, _script(tmp_path)), compute_budget=budget)


def test_failed_run_releases_the_reservation(tmp_path):
    budget = SessionComputeBudget()
    budget.config.tracked = {"sandbox.run": "b1"}
    budget.config.ceilings = {"b1": 10.0}
    spec = _spec(tmp_path, _script(tmp_path))
    spec.ivisor_bin = "/nonexistent/ivisor"

    with pytest.raises(SandboxUnsupported):
        run_sandboxed(spec, compute_budget=budget)
    # A run that never happened must not consume the grant.
    assert budget.remaining("b1") == 10.0


def test_reusing_a_run_dir_preserves_workspace_state(tmp_path):
    first = run_sandboxed(_spec(tmp_path, _script(tmp_path)))
    marker = first.staged.workspace / "out" / "state.txt"
    marker.write_text("carried over\n")

    second = run_sandboxed(_spec(tmp_path, _script(tmp_path),
                                 reuse_run_dir=first.staged.run_dir,
                                 run_id=first.run_id))
    assert (second.staged.workspace / "out" / "state.txt").read_text() == \
        "carried over\n"


def test_degraded_trace_yields_indeterminate_outcome(tmp_path):
    warning = "ivisor: IVISOR_TRACE_FD=2 must be >= 3; policy trace -> stderr"
    log = DecisionLog(session_id="s1")
    outcome = run_sandboxed(_spec(tmp_path,
                                  _script(tmp_path, stderr=[warning])),
                            decision_log=log)
    assert outcome.evidence_ok is False
    assert log.records()[0]["decision"]["outcome"] == "indeterminate"
