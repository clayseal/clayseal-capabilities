"""A tiny MCP server standing in for an accounts-payable desk.

    clayseal proxy --policy examples/refund.yaml -- python examples/refund_server.py

It speaks just enough of MCP over stdio to be proxied: `initialize`,
`tools/list`, `tools/call`. Three tools, one of which the policy never grants.

Every executed call is appended to the file named by `argv[1]`, if one is given.
That file is the point. A JSON-RPC error proves the agent was told no; only the
server's own record proves the refund did not happen, and those are different
claims. `examples/02_the_proxy.py` reads it back for exactly that reason.
"""
import json
import pathlib
import sys

TOOLS = [
    {"name": "list_open_refunds",
     "description": "List refunds approved and awaiting payment.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "issue_refund",
     "description": "Pay one approved refund against an invoice.",
     "inputSchema": {"type": "object", "properties": {
         "invoice": {"type": "string"}, "amount": {"type": "number"}},
         "required": ["invoice", "amount"]}},
    # Never granted by examples/refund.yaml. A real AP server exposes it because
    # somebody needs it; this session was not given it, so the agent is never
    # told it exists.
    {"name": "wire_funds",
     "description": "Wire funds to an arbitrary account.",
     "inputSchema": {"type": "object", "properties": {
         "to": {"type": "string"}, "amount": {"type": "number"}},
         "required": ["to", "amount"]}},
]

OPEN = [(f"INV-{i:03d}", 900.00) for i in range(1, 12)]

log = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else None


def _run(name, args):
    """Do the thing, and record that it was done."""
    if log is not None:
        with log.open("a") as fh:
            fh.write(f"{name} {json.dumps(args, sort_keys=True)}\n")
    if name == "list_open_refunds":
        return "; ".join(f"{inv} ${amt:.2f}" for inv, amt in OPEN)
    if name == "issue_refund":
        return f"paid {args.get('invoice')} ${float(args.get('amount', 0)):.2f}"
    if name == "wire_funds":
        return f"wired ${float(args.get('amount', 0)):.2f} to {args.get('to')}"
    return f"unknown tool {name}"


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    method, request_id = msg.get("method"), msg.get("id")
    if method == "initialize":
        result = {"protocolVersion": "2024-11-05",
                  "capabilities": {"tools": {}},
                  "serverInfo": {"name": "ap-desk", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        params = msg.get("params") or {}
        text = _run(params.get("name"), params.get("arguments") or {})
        result = {"content": [{"type": "text", "text": text}]}
    else:
        continue                                # notifications need no reply
    print(json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}),
          flush=True)
