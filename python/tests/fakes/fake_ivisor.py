#!/usr/bin/env python3
"""A stand-in for the real `ivisor` binary, for driver tests.

Honors the parts of iVisor's contract the driver depends on:

  fake_ivisor.py [--config FILE] run <script.json> [guest args...]

  * `--config FILE` is parsed with iVisor's `key = value` grammar; an unknown
    key exits 1 with a config-error message on stderr, as the real sentry does.
  * `IVISOR_TRACE_FD=N` (N >= 3) routes policy lines to that fd; N < 3 or a
    dead fd falls back to stderr with the real warning text.
  * `IVISOR_TRACE` gates whether policy lines are emitted at all.

`<script.json>` stands in for the guest ELF and tells this fake what to do:

    {"trace": ["ivisor: policy fs.open verdict=allow path=/work/x", ...],
     "stdout": ["..."], "stderr": ["..."],
     "sleep": 0.0, "exit": 0, "signal": null}

Everything is optional. `signal` makes the process kill itself with that signal
so the driver's exit decoding can be exercised.

This keeps the whole driver test suite free of HVF, codesigning, and Apple
Silicon — it runs anywhere CI does.
"""
from __future__ import annotations

import json
import os
import sys
import time

KNOWN_KEYS = {"ram_mb", "rootfs", "workspace", "compute", "compute_ring_mb",
              "hostd", "allow", "listen", "sandbox"}


def _load_config(path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    with open(path) as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            key, sep, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if not sep:
                _die(f"{path}:{lineno}: expected key = value")
            if key not in KNOWN_KEYS:
                _die(f'{path}:{lineno}: unknown key "{key}"')
            out[key] = value
    return out


def _die(message: str) -> None:
    # Matches the real CLI's failure shape: `ivisor: <error>` + exit 1.
    sys.stderr.write(f"ivisor: {message}\n")
    raise SystemExit(1)


def _open_trace_sink():
    """Mirror crates/ivisor-kernel/src/trace.rs::open_sink."""
    spec = os.environ.get("IVISOR_TRACE_FD")
    if spec is None:
        return sys.stderr
    try:
        fd = int(spec.strip())
    except ValueError:
        sys.stderr.write(
            f'ivisor: IVISOR_TRACE_FD="{spec}" is not a number; '
            "policy trace -> stderr\n")
        return sys.stderr
    if fd < 3:
        sys.stderr.write(
            f"ivisor: IVISOR_TRACE_FD={fd} must be >= 3; policy trace -> stderr\n")
        return sys.stderr
    try:
        os.write(fd, b"")            # liveness probe, as the sentry does
        return os.fdopen(fd, "w", closefd=False)
    except OSError as exc:
        sys.stderr.write(
            f"ivisor: IVISOR_TRACE_FD={fd} unusable ({exc}); "
            "policy trace -> stderr\n")
        return sys.stderr


def main(argv: list[str]) -> int:
    args = list(argv)
    config_path = None
    while args and args[0].startswith("--"):
        flag = args.pop(0)
        if flag == "--config":
            if not args:
                _die("--config needs a file")
            config_path = args.pop(0)
        else:
            args and args.pop(0)     # ignore other flags' values
    if config_path:
        _load_config(config_path)
    if not args or args[0] != "run":
        _die("usage: ivisor [options] run <elf> [guest args...]")
    args.pop(0)
    if not args:
        _die("run needs an elf")
    script_path = args.pop(0)

    try:
        with open(script_path) as fh:
            script = json.load(fh)
    except (OSError, ValueError):
        script = {}

    trace_on = "policy" in os.environ.get("IVISOR_TRACE", "")
    sink = _open_trace_sink()

    # A guest that writes into its workspace. The real sentry's guest does this
    # through the gofer; here the workspace is just a host directory, so the
    # fake writes it directly. Optional and additive — callers that omit it see
    # the previous behaviour exactly.
    for entry in script.get("write", []):
        try:
            target = entry["path"]
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "w") as fh:
                fh.write(entry.get("text", ""))
        except OSError:
            pass

    for line in script.get("stdout", []):
        sys.stdout.write(line + "\n")
    sys.stdout.flush()
    for line in script.get("stderr", []):
        sys.stderr.write(line + "\n")
    sys.stderr.flush()

    if trace_on:
        for line in script.get("trace", []):
            sink.write(line + "\n")
        sink.flush()

    sleep = script.get("sleep")
    if sleep:
        time.sleep(float(sleep))

    signal_no = script.get("signal")
    if signal_no:
        import signal as _signal
        _signal.signal(_signal.SIGTERM, _signal.SIG_DFL)
        os.kill(os.getpid(), int(signal_no))
    return int(script.get("exit", 0))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
