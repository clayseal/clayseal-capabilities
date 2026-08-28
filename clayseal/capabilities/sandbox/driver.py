"""Spawn iVisor and collect its verdict stream.

WHY SPAWN RATHER THAN EMBED: iVisor is a library as well as a binary, but
embedding is not viable for a supervisor. Hypervisor.framework allows one VM
per process, the run call is blocking with no stop handle, it applies an
irreversible Seatbelt profile to its caller, and every binary touching HVF needs
the com.apple.security.hypervisor entitlement. Spawning keeps all of that on the
other side of a process boundary.

THE EVIDENCE CHANNEL: iVisor writes policy verdicts to the fd named by
IVISOR_TRACE_FD. Guest fds are virtualized and only 0/1/2 exist, so a host fd
>= 3 is structurally unreachable from inside the guest, which is what makes
those lines evidence. A guest that knows the format can print policy-shaped
lines to its own stdout/stderr; we collect those separately as
`unverified_claims` and never count them.

Verified against crates/ivisor-kernel/src/trace.rs:96-122: any fd >= 3 named by
IVISOR_TRACE_FD is accepted after a zero-length-write liveness probe. So
subprocess's `pass_fds` is sufficient and we do not need the reference
supervisor's close-then-dup2-onto-fd-3 dance (which exists in Rust because
pipe(2) hands back the lowest free descriptors and a stray fd 3 would collide
with the gofer socket).
"""
from __future__ import annotations

import os
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from clayseal.capabilities.sandbox.verdicts import (
    POLICY_PREFIX,
    PolicyEvent,
    Verdict,
    parse_policy_line,
)

# crates/ivisor-kernel/src/trace.rs emits these when the trace fd is unusable
# and it silently reroutes verdicts to (guest-forgeable) stderr.
_DEGRADED_MARKERS = ("IVISOR_TRACE_FD", "policy trace -> stderr")

# crates/ivisor/src/runtime.rs:614, a syscall handler panic caught by
# catch_unwind kills the thread group with 128 + SIGSYS(31).
HANDLER_PANIC_CODE = 159


class SandboxUnsupported(RuntimeError):
    """The host cannot run iVisor (non-POSIX, or the binary is missing)."""


class ExitKind(str, Enum):
    EXITED = "exited"
    SIGNALED = "signaled"
    HANDLER_PANIC = "handler_panic"
    CONFIG_ERROR = "config_error"
    TIMEOUT = "timeout"
    SPAWN_FAILED = "spawn_failed"


@dataclass(frozen=True)
class IVisorResult:
    """The outcome of one sandboxed run."""

    exit_kind: ExitKind
    exit_code: int | None = None          # guest exit status, u8-truncated
    signal: int | None = None
    events: tuple[PolicyEvent, ...] = ()          # trace fd only, evidence
    unverified_claims: tuple[PolicyEvent, ...] = ()  # guest-authored, never evidence
    trace_degraded: bool = False
    stdout: str = ""
    stderr: str = ""
    wall_seconds: float = 0.0
    cpu_seconds: float | None = None
    argv: tuple[str, ...] = field(default_factory=tuple)

    @property
    def evidence_ok(self) -> bool:
        """False when verdicts fell back to a stream the guest can write.

        Callers must treat a degraded run as producing no verified evidence
        rather than as a clean run with no denials.
        """
        return not self.trace_degraded

    def denials(self) -> tuple[PolicyEvent, ...]:
        return tuple(e for e in self.events if e.verdict is Verdict.DENY)

    def allows(self) -> tuple[PolicyEvent, ...]:
        return tuple(e for e in self.events if e.verdict is Verdict.ALLOW)

    def summary(self) -> dict:
        counts = {v.value: 0 for v in Verdict}
        for event in self.events:
            counts[event.verdict.value] += 1
        counts["unverified_claims"] = len(self.unverified_claims)
        return counts


def run_ivisor(*, ivisor_bin: str, config_path: str | Path, elf: str,
               guest_args: Sequence[str] = (),
               trace: Sequence[str] = ("policy",),
               timeout_s: float | None = 120.0,
               env: dict[str, str] | None = None,
               log_level: str = "info",
               on_event: Callable[[PolicyEvent], None] | None = None,
               ) -> IVisorResult:
    """Run `elf` under iVisor with the policy in `config_path`.

    `on_event` is called as verified verdicts arrive, for live rendering.
    """
    if os.name != "posix":
        raise SandboxUnsupported(
            "iVisor runs on macOS/Apple Silicon; the driver needs POSIX pipes "
            f"and this host is {os.name!r}")

    argv = [str(ivisor_bin), "--config", str(config_path), "run", str(elf),
            *[str(a) for a in guest_args]]
    read_fd, write_fd = os.pipe()
    child_env = dict(os.environ if env is None else env)
    child_env["IVISOR_TRACE"] = ",".join(trace)
    child_env["IVISOR_TRACE_FD"] = str(write_fd)
    child_env["IVISOR_LOG"] = log_level

    events: list[PolicyEvent] = []
    claims: list[PolicyEvent] = []
    out_lines: list[str] = []
    err_lines: list[str] = []
    degraded = threading.Event()

    started = time.monotonic()
    cpu_before = _child_cpu_seconds()
    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, pass_fds=(write_fd,), env=child_env,
            text=True, bufsize=1)
    except FileNotFoundError as exc:
        os.close(read_fd)
        os.close(write_fd)
        raise SandboxUnsupported(
            f"iVisor binary {ivisor_bin!r} not found. Build it (cargo build -p "
            "ivisor on Apple Silicon), copy it, then ad-hoc sign the copy with "
            "the com.apple.security.hypervisor entitlement.") from exc
    except OSError as exc:
        os.close(read_fd)
        os.close(write_fd)
        return IVisorResult(exit_kind=ExitKind.SPAWN_FAILED, stderr=str(exc),
                            argv=tuple(argv))

    # The parent must drop the write end or the reader never sees EOF.
    os.close(write_fd)

    def pump_trace() -> None:
        with os.fdopen(read_fd, "r", errors="replace") as handle:
            for line in handle:
                event = parse_policy_line(line, verified=True,
                                          at_ms=int(time.time() * 1000))
                if event is None:
                    continue
                events.append(event)
                if on_event is not None:
                    on_event(event)

    def pump_stream(stream, sink: list[str], watch_degraded: bool) -> None:
        for line in stream:
            sink.append(line)
            if watch_degraded and all(m in line for m in _DEGRADED_MARKERS):
                degraded.set()
            # Policy-shaped lines here are the guest's own claim, not evidence.
            if line.lstrip().startswith(POLICY_PREFIX):
                claim = parse_policy_line(line.lstrip(), verified=False)
                if claim is not None:
                    claims.append(claim)
        stream.close()

    threads = [
        threading.Thread(target=pump_trace, daemon=True),
        threading.Thread(target=pump_stream,
                         args=(proc.stdout, out_lines, False), daemon=True),
        threading.Thread(target=pump_stream,
                         args=(proc.stderr, err_lines, True), daemon=True),
    ]
    for thread in threads:
        thread.start()

    timed_out = False
    try:
        returncode = proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        returncode = proc.wait()
    for thread in threads:
        thread.join(timeout=5.0)

    wall = time.monotonic() - started
    cpu_after = _child_cpu_seconds()
    cpu = None if (cpu_before is None or cpu_after is None) else cpu_after - cpu_before

    stdout, stderr = "".join(out_lines), "".join(err_lines)
    kind, code, signal_no = _classify_exit(returncode, timed_out,
                                           bool(events), stderr)
    return IVisorResult(
        exit_kind=kind, exit_code=code, signal=signal_no,
        events=tuple(events), unverified_claims=tuple(claims),
        trace_degraded=degraded.is_set(), stdout=stdout, stderr=stderr,
        wall_seconds=wall, cpu_seconds=cpu, argv=tuple(argv))


def _classify_exit(returncode: int, timed_out: bool, saw_events: bool,
                   stderr: str) -> tuple[ExitKind, int | None, int | None]:
    """Decode iVisor's exit status.

    The guest's own code is truncated to u8 by the CLI, a fatal guest signal
    surfaces as 128 + signo, and a caught syscall-handler panic as 159. Exit 1
    is ambiguous: it is both a CLI/config error and a perfectly ordinary guest
    failure, so we only call it a config error when nothing ran: no verdict
    ever reached the trace fd and the sentry printed its own error prefix.
    """
    if timed_out:
        return ExitKind.TIMEOUT, None, None
    if returncode < 0:
        return ExitKind.SIGNALED, None, -returncode
    if returncode == HANDLER_PANIC_CODE:
        return ExitKind.HANDLER_PANIC, returncode, None
    if returncode > 128:
        return ExitKind.SIGNALED, returncode, returncode - 128
    if returncode == 1 and not saw_events and _looks_like_config_error(stderr):
        return ExitKind.CONFIG_ERROR, returncode, None
    return ExitKind.EXITED, returncode, None


def _looks_like_config_error(stderr: str) -> bool:
    # The CLI reports its own failures as `ivisor: <error>` before any guest
    # code runs (crates/ivisor/src/main.rs:118).
    return any(line.startswith("ivisor: ") and "policy" not in line
               for line in stderr.splitlines())


def _child_cpu_seconds() -> float | None:
    """CPU seconds charged to reaped children so far.

    Impure by construction: it counts every child this process has reaped, not
    just ours. Recorded for observability; the compute budget charges wall
    time, which is what a VM run actually consumes.
    """
    try:
        import resource
    except ImportError:
        return None
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime
