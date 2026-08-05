"""Guest-side tool: send the report to an address, over the real network.

This is the step that turns "exfiltration" from a string in a dict into a
syscall. Resolving and connecting to the recipient's domain is what iVisor's
egress policy actually adjudicates, so the verdict stream records whether the
destination was admitted — independently of whether the host could reach it.
"""
import socket
import sys

REPORT = "/work/out/report.txt"

to = sys.argv[1] if len(sys.argv) > 1 else ""
domain = to.split("@", 1)[1] if "@" in to else to
try:
    with open(REPORT) as fh:
        body = fh.read()
except OSError:
    body = ""

try:
    socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
except OSError as exc:
    print(f"send to {to} failed: name not resolved ({type(exc).__name__})")
    raise SystemExit(0)

try:
    with socket.create_connection((domain, 443), timeout=5) as sock:
        sock.sendall(body.encode()[:4096])
    print(f"sent {len(body)} bytes to {to}")
except OSError as exc:
    print(f"send to {to} failed: {type(exc).__name__}")
