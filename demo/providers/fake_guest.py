"""Synthesize a fake-sentry script for one tool call.

READ THIS BEFORE TRUSTING A GREEN RUN. This module MODELS iVisor's behaviour; it
does not verify it. A `--fake-guest` run exercises the whole harness, the
ladder, epochs, config rendering, the trace-fd path, the reducer, expectations,
and the exit code, on any machine, with no HVF and no codesigning. What it
cannot do is tell you whether iVisor really denies what we believe it denies.
Only the gated real-sentry test does that.

The verdict shapes below were copied from observed output of the real signed
binary, including the detail that matters most for grading: an allowlisted
domain that does not resolve still yields `verdict=allow` with
`rcode=NXDOMAIN`, while a domain outside the allow-list yields `verdict=deny
reason=not-allowlisted`. The verdict records the policy decision, not the
network outcome.
"""
from __future__ import annotations

import json
from pathlib import Path

WORKSPACE = "/work"


def _domain(address: str) -> str:
    return address.split("@", 1)[1] if "@" in address else address


def _allows(domain: str, allow: tuple[str, ...]) -> bool:
    # iVisor matches exactly; a suffix rule would be a different (looser) policy.
    return domain in allow


def synthesize(tool: str, args: dict, *, epoch, scenario, path: Path,
               summary_text: str = "") -> Path:
    """Write the JSON script the fake sentry will execute for this call."""
    trace: list[str] = []
    stdout: list[str] = []
    writes: list[dict] = []
    staged = set(epoch.base_files)
    workspace = epoch.workspace

    if tool == "list_tickets":
        ids = sorted(k.rsplit("/", 1)[-1][:-4] for k in staged
                     if k.startswith("data/tickets/"))
        if ids:
            for ticket_id in ids:
                trace.append(_fs_allow(f"{WORKSPACE}/data/tickets/{ticket_id}.txt"))
            stdout.append(", ".join(ids))
        else:
            trace.append(_fs_miss(f"{WORKSPACE}/data/tickets"))
            stdout.append("ticket store unavailable (FileNotFoundError)")

    elif tool == "read_ticket":
        ticket_id = str(args.get("id", ""))
        key = f"data/tickets/{ticket_id}.txt"
        if key in staged:
            trace.append(_fs_allow(f"{WORKSPACE}/{key}"))
            stdout.append(scenario.tickets.get(ticket_id, "").strip())
        else:
            # Quarantine looks like this: absence, not refusal.
            trace.append(_fs_miss(f"{WORKSPACE}/{key}"))
            stdout.append(f"ticket {ticket_id!r} unavailable (FileNotFoundError)")

    elif tool == "write_summary":
        target = f"{WORKSPACE}/out/summary.md"
        trace.append(_fs_allow(target, flags="0o1101"))
        body = summary_text or str(args.get("text", ""))
        writes.append({"path": str(workspace / "out" / "summary.md"),
                       "text": body if body.endswith("\n") else body + "\n"})
        stdout.append(f"wrote {len(body)} bytes to {target}")

    elif tool == "send_email":
        to = str(args.get("to", ""))
        domain = _domain(to)
        if _allows(domain, epoch.allow):
            trace.append(
                f"ivisor: policy dns.query verdict=allow name={domain} qtype=1 "
                "rcode=NXDOMAIN reason=no-addresses")
            stdout.append(f"send to {to} failed: name not resolved (gaierror)")
        else:
            trace.append(
                f"ivisor: policy dns.query verdict=deny name={domain} qtype=1 "
                "reason=not-allowlisted rcode=NXDOMAIN")
            stdout.append(f"send to {to} failed: name not resolved (gaierror)")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(
        {"trace": trace, "stdout": stdout, "write": writes, "exit": 0}))
    return path


def _fs_allow(path: str, *, flags: str = "0o0") -> str:
    return (f"ivisor: policy fs.open verdict=allow root=workspace "
            f"path={path} flags={flags}")


def _fs_miss(path: str) -> str:
    return (f"ivisor: policy fs.open verdict=miss root=workspace "
            f"path={path} flags=0o0 errno=ENOENT")
