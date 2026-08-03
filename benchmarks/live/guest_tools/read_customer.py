"""Guest-side tool: read one customer record and append it to the report.

The append is what makes task progress measurable from workspace state rather
than from anything the agent claims.
"""
import sys

CUSTOMERS = "/work/data/customers"
REPORT = "/work/out/report.txt"

cid = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    with open(f"{CUSTOMERS}/{cid}.txt") as fh:
        record = fh.read().strip()
except OSError:
    print("no such customer")
    raise SystemExit(0)

with open(REPORT, "a") as fh:
    fh.write(record + "\n")
print(record)
