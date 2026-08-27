"""The gateway in front of the tools, not inside the agent.

    python examples/02_the_proxy.py

This is the scenario the README opens with, run end to end. An agent with a
legitimate goal and a legitimate tool grant issues eleven refunds of $900
against a $1,000 ceiling. Every call passes a per-call check, because every call
is individually within policy. The session is not.

`examples/01_gateway.py` shows the same gateway as a library call your harness
chooses to make. This shows it as a process the calls have to cross, which is
the difference between a control and a convention: here the agent connects to
the proxy, the proxy runs the real server, and a refused call is answered with a
JSON-RPC error that the server subprocess never sees.

Everything below is the shipped path. The proxy is the one `clayseal proxy`
runs, and the equivalent command line is:

    clayseal proxy --policy examples/refund.yaml -- python examples/refund_server.py
"""
import json
import pathlib
import sys
import tempfile

from clayseal.capabilities.mcp_proxy import McpProxy, run_stdio_proxy
from clayseal.capabilities.policy import load_policy

HERE = pathlib.Path(__file__).resolve().parent


def frame(request_id, method, **params):
    return json.dumps({"jsonrpc": "2.0", "id": request_id,
                       "method": method, "params": params})


# 1. The authority, read from the same YAML the CLI reads. `from_policy` is what
#    wires the five fields that have to agree with the document; building the
#    proxy by hand is how you get a correct CLI and an incorrect everything else.
policy = load_policy(HERE / "refund.yaml")
for finding in policy.lint():
    print(f"  lint: {finding.level:8} {finding.code}")

notes: list[str] = []
proxy = McpProxy.from_policy(policy, log=notes.append)
print(f"\npolicy {policy.digest()[:19]} under profile {policy.profile}")
ceiling = policy.value_budget.config.ceilings.get("refunds", "?")
print(f"ceiling ${ceiling} on refunds\n")

# 2. What the agent sends. Eleven refunds of $900 against eleven invoices, then
#    a wire the policy never granted. The eleven are the story; the wire is here
#    because a tool outside the grant is a different refusal with a different
#    reason, and both belong in a demonstration.
requests = [frame(0, "initialize"), frame(1, "tools/list")]
requests.append(frame(2, "tools/call", name="list_open_refunds", arguments={}))
for i in range(1, 12):
    requests.append(frame(10 + i, "tools/call", name="issue_refund",
                          arguments={"invoice": f"INV-{i:03d}", "amount": 900.00}))
requests.append(frame(99, "tools/call", name="wire_funds",
                      arguments={"to": "ops-float", "amount": 50.00}))


class Lines:
    """Stands in for the agent's end of the pipe."""

    def __init__(self, lines): self._lines = list(lines)
    def __iter__(self): return iter(self._lines)


class Sink:
    def __init__(self): self.out = []
    def write(self, s): self.out.append(s)
    def flush(self): pass


# 3. Run it. The server records every call it actually executed to `ledger`,
#    because "the agent was told no" and "the effect did not happen" are
#    different claims and only the second one matters.
with tempfile.TemporaryDirectory() as tmp:
    ledger = pathlib.Path(tmp) / "executed.log"
    sink = Sink()
    run_stdio_proxy(
        proxy,
        [sys.executable, str(HERE / "refund_server.py"), str(ledger)],
        stdin=Lines(requests),
        stdout=sink,
    )
    executed = ledger.read_text().splitlines() if ledger.exists() else []

replies = {}
for line in "".join(sink.out).splitlines():
    if line.strip():
        msg = json.loads(line)
        replies[msg.get("id")] = msg

# 4. The transcript.
advertised = [t["name"] for t in replies[1]["result"]["tools"]]
print(f"tools advertised to the agent: {', '.join(advertised)}")
print("  (the server offers wire_funds; the policy does not grant it, so the "
      "agent is never told it exists)\n")

for request in requests[2:]:
    sent = json.loads(request)
    args = sent["params"]["arguments"]
    reply = replies.get(sent["id"], {})
    label = sent["params"]["name"]
    detail = f"{args.get('invoice') or args.get('to') or ''}"
    if "error" in reply:
        print(f"  DENY {label:18} {detail:9} {reply['error']['message']}")
    else:
        text = reply["result"]["content"][0]["text"]
        print(f"  ok   {label:18} {detail:9} "
              f"{text if len(text) < 58 else text[:55] + '...'}")

# 5. The evidence, from the server rather than from this script.
print(f"\nthe server executed {len(executed)} call(s):")
for line in executed:
    print(f"  {line}")
print("\n" + "\n".join(notes[-1:]))
print(
    "\nTen refunds were refused and not one of them reached the tool. Every\n"
    "$900 was inside the operator's per-refund discretion, so a gate deciding\n"
    "one call at a time allows all eleven. The second one is what exhausts a\n"
    "$1,000 session ceiling, and only something holding the running total\n"
    "between calls can see that."
)
