"""End-to-end tests against the real iVisor sentry.

Opt in, because these need Apple Silicon, a built sentry, and a guest rootfs:

    cp <iVisor>/target/release/ivisor /tmp/ivisor-signed
    codesign --force --sign - --entitlements <iVisor>/entitlements.plist \\
        /tmp/ivisor-signed
    IVISOR_E2E=1 IVISOR_BIN=/tmp/ivisor-signed \\
    IVISOR_ROOTFS=<iVisor>/guests/rootfs \\
        pytest python/tests/test_ivisor_e2e.py -q

Sign a *copy*: signing a binary another process is executing can kill it.

Everything else about the driver is covered by the fake binary in
test_sandbox_driver.py; what only the real sentry can prove is that the trace-fd
contract holds and that a guest genuinely cannot forge a verdict.
"""
import os
import textwrap
from pathlib import Path

import pytest

from agentauth.capabilities.hardening.egress_policy import EgressPolicy
from agentauth.capabilities.sandbox.session import SandboxRunSpec, run_sandboxed
from agentauth.capabilities.sandbox.verdicts import Verdict

pytestmark = pytest.mark.skipif(
    not os.environ.get("IVISOR_E2E"),
    reason="set IVISOR_E2E=1 with IVISOR_BIN and IVISOR_ROOTFS to run")

IVISOR_BIN = os.environ.get("IVISOR_BIN", "ivisor")
IVISOR_ROOTFS = os.environ.get("IVISOR_ROOTFS", "")
BLOCKED_HOST = "203.0.113.10"      # TEST-NET-3: never routable
ALLOWED_DOMAIN = "example.com"


@pytest.fixture(scope="module", autouse=True)
def require_rootfs():
    if not IVISOR_ROOTFS or not Path(IVISOR_ROOTFS).is_dir():
        pytest.skip(f"IVISOR_ROOTFS={IVISOR_ROOTFS!r} is not a directory")


def _guest_python() -> str:
    return str(Path(IVISOR_ROOTFS) / "usr" / "bin" / "python3")


def _run(tmp_path, source: str, *, egress=None, timeout_s=90.0):
    script = tmp_path / "guest.py"
    script.write_text(textwrap.dedent(source))
    spec = SandboxRunSpec(
        elf=_guest_python(), guest_args=("-u", "/work/task/guest.py"),
        rootfs=IVISOR_ROOTFS, run_root=tmp_path / "runs",
        ivisor_bin=IVISOR_BIN, egress=egress, timeout_s=timeout_s,
        extra_files={"task/guest.py": script})
    return run_sandboxed(spec)


def test_guest_write_produces_a_verified_filesystem_verdict(tmp_path):
    outcome = _run(tmp_path, """
        with open("/work/out/report.txt", "w") as fh:
            fh.write("hello from the guest\\n")
        print("wrote it")
    """)
    assert outcome.result.exit_code == 0
    assert outcome.evidence_ok

    writes = [e for e in outcome.result.events
              if e.event == "fs.open" and "/work/out/report.txt" in e.subject()]
    assert writes, f"no fs.open verdict for the write; got {outcome.result.summary()}"
    assert writes[0].verdict is Verdict.ALLOW
    assert writes[0].verified

    # The host side of the workspace really holds what the guest wrote.
    assert (outcome.staged.workspace / "out" / "report.txt").read_text() == \
        "hello from the guest\n"
    assert "out/report.txt" in outcome.delta["created"]


def test_non_allowlisted_egress_is_denied_at_the_syscall_boundary(tmp_path):
    outcome = _run(tmp_path, f"""
        import socket
        try:
            socket.create_connection(("{BLOCKED_HOST}", 443), timeout=5)
            print("CONNECTED")
        except OSError as exc:
            print("refused:", type(exc).__name__)
    """, egress=EgressPolicy(allowed_domains={ALLOWED_DOMAIN}))

    denials = [e for e in outcome.result.events if e.event == "net.connect"
               and e.verdict is Verdict.DENY]
    assert denials, f"expected a denied connect; got {outcome.result.summary()}"
    assert BLOCKED_HOST in denials[0].get("dst")
    assert denials[0].get("reason") == "not-allowlisted"
    assert "CONNECTED" not in outcome.result.stdout

    # The denial reaches the attestation and the lowered policy is recorded.
    assert outcome.sandboxing["verdicts"]["deny"] >= 1
    assert outcome.sandboxing["lowering"]["lowered_domains"] == [ALLOWED_DOMAIN]


def test_the_guest_cannot_forge_a_verdict(tmp_path):
    """The property the whole evidence model rests on.

    The guest prints a perfectly well-formed allow line to its own stdout. It
    must land in unverified_claims and never in the verified stream, because
    guest fds are virtualized and the trace fd is unreachable from inside.
    """
    forged = (f"ivisor: policy net.connect verdict=allow "
              f"dst={BLOCKED_HOST}:443 status=ok")
    outcome = _run(tmp_path, f"""
        import sys
        print({forged!r})
        print({forged!r}, file=sys.stderr)
    """)

    assert forged in outcome.result.stdout
    assert len(outcome.result.unverified_claims) >= 1
    assert all(not c.verified for c in outcome.result.unverified_claims)

    # No verified event ever allowed that destination.
    assert not [e for e in outcome.result.events
                if e.verdict is Verdict.ALLOW and BLOCKED_HOST in e.subject()]
    # And the forgery never reaches the persisted evidence.
    trace = (outcome.staged.run_dir / "trace.jsonl").read_text()
    assert BLOCKED_HOST not in trace


def test_guest_cannot_see_unstaged_host_files(tmp_path):
    """Path scope is enforced by absence: what was not staged is not there."""
    secret = tmp_path / "secret.txt"
    secret.write_text("do not leak\n")
    outcome = _run(tmp_path, f"""
        for path in ({str(secret)!r}, "/work/secret.txt", "/etc/shadow"):
            try:
                print(path, "->", open(path).read()[:20])
            except OSError as exc:
                print(path, "->", type(exc).__name__)
    """)
    assert "do not leak" not in outcome.result.stdout


def test_run_artifact_is_re_runnable_by_hand(tmp_path):
    outcome = _run(tmp_path, "print('artifact check')")
    config = outcome.staged.run_dir / "ivisor.conf"
    text = config.read_text()
    assert f"rootfs = {IVISOR_ROOTFS}" in text
    assert str(outcome.staged.workspace) in text
    # Exactly the knobs iVisor accepts — an unknown key would abort the run.
    keys = {line.split(" = ")[0] for line in text.splitlines()
            if not line.startswith("#")}
    assert keys <= {"ram_mb", "rootfs", "workspace", "compute",
                    "compute_ring_mb", "hostd", "allow", "listen", "sandbox"}


def test_trace_fd_contract_holds_with_pass_fds(tmp_path):
    """`pass_fds` alone satisfies IVISOR_TRACE_FD (any fd >= 3), so the driver
    needs no dup2-onto-3 dance. If that ever regressed, the sentry would warn
    and reroute verdicts to stderr — which is what trace_degraded detects."""
    outcome = _run(tmp_path, "open('/work/out/x.txt', 'w').write('x')")
    assert outcome.result.trace_degraded is False
    assert outcome.result.events, "no verdicts arrived on the trace fd"
    assert all(e.verified for e in outcome.result.events)
