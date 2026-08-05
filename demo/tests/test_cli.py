# ruff: noqa: PLW1510  # these calls inspect returncode deliberately
"""CLI smoke tests.

These exist because the rest of the suite imports demo modules directly, so a
broken import in `demo.cli` — a stray dependency, a typo in a subcommand — would
pass every other test and fail only when someone actually ran the demo. That
happened once; this is the guard.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
FAKE = REPO / "python" / "tests" / "fakes" / "fake_ivisor.py"


def _demo(*args, expect: int | None = None) -> subprocess.CompletedProcess:
    proc = subprocess.run([sys.executable, "-m", "demo", *args], cwd=REPO,
                          capture_output=True, text=True, timeout=300)
    if expect is not None:
        assert proc.returncode == expect, proc.stdout + proc.stderr
    return proc


def test_cli_imports_without_optional_dependencies():
    # The failure mode this file exists for.
    subprocess.run([sys.executable, "-c", "import demo.cli"], cwd=REPO,
                   check=True, capture_output=True, timeout=60)


def test_help_works():
    assert "run" in _demo("--help", expect=0).stdout


@pytest.mark.parametrize("level", ["baseline", "suspect", "contained",
                                   "quarantined"])
def test_config_prints_a_compiled_policy(level, tmp_path):
    out = _demo("config", "--level", level, "--rootfs", "/rootfs",
                "--run-root", str(tmp_path), expect=0).stdout
    assert "ram_mb = 1024" in out
    assert "enforced at" in out
    if level in ("contained", "quarantined"):
        assert "allow =" not in out          # deny-all
    else:
        assert "allow = acme-internal.com" in out


def test_a_full_run_exits_zero_when_every_expectation_holds(tmp_path):
    proc = _demo("run", "ticket-triage", "--provider", "mock", "--plain",
                 "--no-color", "--fake-guest", "--run-root", str(tmp_path),
                 expect=0)
    assert "digest unchanged" in proc.stdout
    assert "CONTAINED" in proc.stdout


def test_the_benign_control_exits_zero(tmp_path):
    _demo("run", "ticket-triage-benign", "--provider", "benign", "--plain",
          "--no-color", "--fake-guest", "--run-root", str(tmp_path), expect=0)


def test_record_then_replay_round_trips(tmp_path):
    recording = tmp_path / "session.jsonl"
    _demo("run", "ticket-triage", "--provider", "mock", "--plain", "--no-color",
          "--fake-guest", "--run-root", str(tmp_path / "runs"),
          "--record", str(recording), expect=0)

    header = json.loads(recording.read_text().splitlines()[0])
    assert header["kind"] == "header"
    assert header["scenario"] == "ticket-triage"

    out = _demo("replay", str(recording), "--plain", "--no-color",
                "--speed", "1000", expect=0).stdout
    # A replay must never present itself as live containment.
    assert "replay(mock)" in out


def test_fake_guest_overrides_a_real_binary_in_the_environment(tmp_path,
                                                               monkeypatch):
    """--fake-guest must not defer to IVISOR_BIN.

    If it did, running the CLI tests in a shell that had exported IVISOR_BIN
    for the e2e tests would hand the real sentry a JSON script as its ELF.
    """
    import os

    env = dict(os.environ, IVISOR_BIN="/nonexistent/real-ivisor",
               IVISOR_ROOTFS="/nonexistent/rootfs")
    proc = subprocess.run(
        [sys.executable, "-m", "demo", "run", "ticket-triage", "--provider",
         "mock", "--plain", "--no-color", "--fake-guest",
         "--run-root", str(tmp_path)],
        cwd=REPO, capture_output=True, text=True, timeout=300, env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_missing_sandbox_configuration_is_an_actionable_error(tmp_path):
    import os

    # Explicitly cleared: the point is what happens with NO sandbox configured,
    # and this suite is often run in a shell that exported both for the e2e
    # tests.
    env = {k: v for k, v in os.environ.items()
           if k not in ("IVISOR_BIN", "IVISOR_ROOTFS")}
    proc = subprocess.run(
        [sys.executable, "-m", "demo", "run", "ticket-triage", "--provider",
         "mock", "--plain", "--run-root", str(tmp_path)],
        cwd=REPO, capture_output=True, text=True, timeout=300, env=env)
    assert proc.returncode == 2
    assert "--fake-guest" in proc.stderr


def test_committed_recording_still_replays():
    """The recording ships so the demo works on a plane. Keep it loadable."""
    session = REPO / "demo" / "sessions" / "ticket-triage-mock.jsonl"
    if not session.exists():
        pytest.skip("no committed session")
    out = _demo("replay", str(session), "--plain", "--no-color",
                "--speed", "1000", expect=0).stdout
    assert "expectations" in out
