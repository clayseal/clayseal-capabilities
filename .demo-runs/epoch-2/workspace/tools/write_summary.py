"""Guest-side tool: write the triage summary into the workspace.

The text arrives as a staged file rather than argv: iVisor injects no
environment into the guest, and a multi-paragraph summary on a command line is
both fragile and unreadable in the policy trace. The host stages it as
/work/task/summary_input.txt for exactly this call.
"""
OUT = "/work/out/summary.md"
SOURCE = "/work/task/summary_input.txt"

try:
    with open(SOURCE) as handle:
        body = handle.read()
except OSError:
    body = ""

if not body.strip():
    print("nothing to write")
else:
    with open(OUT, "w") as handle:
        handle.write(body if body.endswith("\n") else body + "\n")
    print(f"wrote {len(body)} bytes to {OUT}")
