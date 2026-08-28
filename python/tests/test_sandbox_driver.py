"""Driver tests against a fake iVisor binary.

No HVF, no codesigning, no Apple Silicon, these run wherever CI does. The real
sentry is exercised separately in test_ivisor_e2e.py.
"""
import json
from pathlib import Path

import pytest

from clayseal.capabilities.sandbox.config import IVisorConfig
from clayseal.capabilities.sandbox.driver import (
    ExitKind,
    SandboxUnsupported,
    run_ivisor,
)
from clayseal.capabilities.sandbox.verdicts import Verdict

FAKE = Path(__file__).parent / "fakes" / "fake_ivisor.py"

DENY_LINE = ("ivisor: policy net.connect verdict=deny dst=203.0.113.10:443 "
             "reason=not-allowlisted errno=ECONNREFUSED")
ALLOW_LINE = "ivisor: policy fs.open verdict=allow root=workspace path=/work/a.txt"


@pytest.fixture
def sandbox(tmp_path):
    """A (config_path, make_script) pair pointing at the fake binary."""
    cfg = IVisorConfig(rootfs=str(tmp_path / "rf"), workspace=str(tmp_path / "ws"))
    config_path = tmp_path / "ivisor.conf"
    config_path.write_text(cfg.render())

    def make_script(**script) -> str:
        path = tmp_path / "script.json"
        path.write_text(json.dumps(script))
        return str(path)

    return config_path, make_script


def _run_fake(config_path, script_path, **kwargs):
    return run_ivisor(ivisor_bin=str(FAKE), config_path=config_path,
                      elf=script_path, timeout_s=30.0, **kwargs)


def test_verified_verdicts_arrive_on_the_trace_fd(sandbox):
    config_path, make_script = sandbox
    result = _run_fake(config_path, make_script(trace=[ALLOW_LINE, DENY_LINE]))
    assert result.exit_kind is ExitKind.EXITED
    assert result.exit_code == 0
    assert len(result.events) == 2
    assert all(e.verified for e in result.events)
    assert result.denials()[0].get("dst") == "203.0.113.10:443"
    assert result.summary() == {"allow": 1, "deny": 1, "miss": 0,
                                "unverified_claims": 0}


def test_a_guest_forged_verdict_is_never_evidence(sandbox):
    """The core security property: the guest can print anything it likes to its
    own stdout/stderr, and none of it counts as a verdict."""
    config_path, make_script = sandbox
    forged_allow = ("ivisor: policy net.connect verdict=allow "
                    "dst=203.0.113.10:443 status=ok")
    result = _run_fake(config_path, make_script(
        trace=[DENY_LINE], stdout=[forged_allow], stderr=[forged_allow]))

    # The real denial is evidence; the forgeries are not.
    assert [e.verdict for e in result.events] == [Verdict.DENY]
    assert all(e.verified for e in result.events)
    assert len(result.unverified_claims) == 2
    assert not any(c.verified for c in result.unverified_claims)
    # And the forged allow must not show up in the allow set.
    assert result.allows() == ()


def test_trace_degraded_when_the_sentry_falls_back_to_stderr(sandbox):
    config_path, make_script = sandbox
    warning = ("ivisor: IVISOR_TRACE_FD=2 must be >= 3; policy trace -> stderr")
    result = _run_fake(config_path, make_script(stderr=[warning]))
    assert result.trace_degraded is True
    assert result.evidence_ok is False


def test_clean_run_is_not_degraded(sandbox):
    config_path, make_script = sandbox
    result = _run_fake(config_path, make_script(trace=[ALLOW_LINE]))
    assert result.trace_degraded is False
    assert result.evidence_ok is True


def test_guest_exit_code_is_reported(sandbox):
    config_path, make_script = sandbox
    result = _run_fake(config_path, make_script(exit=7))
    assert result.exit_kind is ExitKind.EXITED
    assert result.exit_code == 7


def test_handler_panic_is_distinguished(sandbox):
    config_path, make_script = sandbox
    result = _run_fake(config_path, make_script(exit=159))
    assert result.exit_kind is ExitKind.HANDLER_PANIC


def test_fatal_signal_is_decoded(sandbox):
    config_path, make_script = sandbox
    result = _run_fake(config_path, make_script(signal=9))
    assert result.exit_kind is ExitKind.SIGNALED
    assert result.signal == 9


def test_config_error_is_distinguished_from_a_guest_exiting_one(sandbox, tmp_path):
    # An unknown key aborts the sentry before any guest code runs.
    bad = tmp_path / "bad.conf"
    bad.write_text("nonsense_key = 1\n")
    config_path, make_script = sandbox
    result = _run_fake(bad, make_script())
    assert result.exit_kind is ExitKind.CONFIG_ERROR

    # A guest that merely exits 1 after producing verdicts is NOT a config error.
    ran = _run_fake(config_path, make_script(trace=[ALLOW_LINE], exit=1))
    assert ran.exit_kind is ExitKind.EXITED
    assert ran.exit_code == 1


def test_timeout_kills_the_guest(sandbox):
    config_path, make_script = sandbox
    result = run_ivisor(ivisor_bin=str(FAKE), config_path=config_path,
                        elf=make_script(sleep=30), timeout_s=0.5)
    assert result.exit_kind is ExitKind.TIMEOUT


def test_on_event_streams_verdicts_in_order(sandbox):
    config_path, make_script = sandbox
    seen = []
    _run_fake(config_path, make_script(trace=[ALLOW_LINE, DENY_LINE]),
              on_event=seen.append)
    assert [e.verdict for e in seen] == [Verdict.ALLOW, Verdict.DENY]


def test_stdout_and_stderr_are_captured(sandbox):
    config_path, make_script = sandbox
    result = _run_fake(config_path,
                       make_script(stdout=["hello out"], stderr=["hello err"]))
    assert "hello out" in result.stdout
    assert "hello err" in result.stderr


def test_missing_binary_raises_actionable_error(sandbox):
    config_path, make_script = sandbox
    with pytest.raises(SandboxUnsupported, match="not found"):
        run_ivisor(ivisor_bin="/nonexistent/ivisor", config_path=config_path,
                   elf=make_script(), timeout_s=5.0)


def test_trace_off_yields_no_events(sandbox):
    # Belt and braces: with policy tracing disabled there is no evidence at all,
    # which must read as "no evidence", not "no denials".
    config_path, make_script = sandbox
    result = _run_fake(config_path, make_script(trace=[DENY_LINE]), trace=())
    assert result.events == ()


def test_wall_time_is_measured(sandbox):
    config_path, make_script = sandbox
    result = _run_fake(config_path, make_script(sleep=0.2))
    assert result.wall_seconds >= 0.2
