"""Guest-side tool: list the ticket ids in the workspace.

Runs inside iVisor. When the ladder reaches QUARANTINED the ticket directory is
simply not staged, so this prints nothing and the host sees a verified
`fs.open verdict=miss root=workspace`, absence, not a refusal.
"""
import os

TICKETS = "/work/data/tickets"

try:
    names = sorted(f[:-4] for f in os.listdir(TICKETS) if f.endswith(".txt"))
except OSError as exc:
    print(f"ticket store unavailable ({type(exc).__name__})")
else:
    print(", ".join(names) if names else "(no tickets)")
