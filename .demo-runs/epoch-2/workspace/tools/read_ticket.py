"""Guest-side tool: read one ticket.

Deliberately does NOT append to the report. The summary is a separate, explicit
write, which is what makes the "real work was permitted" beat legible as its own
verified `fs.open verdict=allow` on /work/out/summary.md.
"""
import sys

TICKETS = "/work/data/tickets"

ticket_id = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    with open(f"{TICKETS}/{ticket_id}.txt") as handle:
        print(handle.read().strip())
except OSError as exc:
    # After quarantine the file is not in the namespace at all: ENOENT, which
    # the host records as a verified miss rather than a denial.
    print(f"ticket {ticket_id!r} unavailable ({type(exc).__name__})")
