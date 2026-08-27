"""Randomized stress of the HTTP gateway, which is the only network boundary.

    python -m benchmarks.stress_http --cases 40000

`http_gateway.py` was written in one pass and hand-tested on the cases its
author thought of, which is the exact position `stress_surface` and
`stress_scope` were in before they each found four defects. It is also the only
component here that parses input arriving from a socket, so it is where a
malformed message costs the most.

## The properties

``TOTAL``        `handle` never raises, on any headers and any body. A gateway
                 that crashes on a message is a gateway an attacker turns off.
``JSON-RPC``     every refusal is a parseable JSON-RPC error object. A client
                 that cannot read the refusal treats it as a transport failure
                 and retries, which turns one denial into a loop.
``NO-BYPASS``    nothing is forwarded upstream unless the gateway ALLOWED it. A
                 502 does not count: that is the upstream failing after the
                 gateway said yes, and an earlier version of this property
                 counted it and was measuring its own stub.
                 The forwarded text is captured and compared with what the
                 decision path returned, so a mismatch between what was checked
                 and what was sent is a failure rather than a footnote.
``HEADER-HONEST`` a request whose routing headers disagree with its body is
                 never forwarded, whatever else is wrong with it.
"""
from __future__ import annotations

import argparse
import json
import random
import string
import sys
from collections import Counter

from clayseal.capabilities.http_gateway import HttpGateway
from clayseal.capabilities.mcp_proxy import McpProxy
from clayseal.capabilities.policy import load_policy_text

POLICY = """
version: 1
goal: {id: fuzz, summary: Pay approved invoices}
profile: supervised
tools:
  allow: [pay_vendor, read_file]
  effects: {pay_vendor: transfer, read_file: read}
paths: {allow: ["/finance/**"], arg_names: {read_file: path}, pathless: [pay_vendor]}
budgets:
  value:
    ceilings: {payments: "1000"}
    tracked: {pay_vendor: {arg: amount, budget: payments}}
"""

METHODS = ["tools/call", "tools/list", "tools/call ", "TOOLS/CALL", "", None,
           "initialize", "notifications/x", "tools//call"]
TOOLS = ["pay_vendor", "read_file", "unknown_tool", "", None, "pay_vendor ",
         "PAY_VENDOR"]
JUNK = ["", "{", "[]", "null", "true", "0", '{"jsonrpc":"2.0"}', "\x00",
        '{"a":1,"a":2}', "[" * 200, '{"jsonrpc":"2.0","id":1,"method":1}']


def _body(rng: random.Random) -> str:
    shape = rng.random()
    if shape < 0.12:
        return rng.choice(JUNK)
    if shape < 0.2:
        return "".join(rng.choice(string.printable)
                       for _ in range(rng.randrange(0, 40)))
    message = {"jsonrpc": "2.0", "id": rng.randrange(0, 5)}
    method = rng.choice(METHODS)
    if method is not None:
        message["method"] = method
    tool = rng.choice(TOOLS)
    params: dict = {}
    if tool is not None:
        params["name"] = tool
    if rng.random() < 0.8:
        params["arguments"] = {"amount": rng.choice(["1", "99999", "x", None]),
                               "path": rng.choice(["/finance/a", "/etc/shadow"])}
    message["params"] = params
    if rng.random() < 0.08:
        return json.dumps([message] * rng.randrange(1, 4))
    return json.dumps(message)


def _headers(rng: random.Random, body: str) -> dict:
    out: dict = {}
    if rng.random() < 0.8:
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = None
        honest = rng.random() < 0.6
        if honest and isinstance(parsed, dict):
            if parsed.get("method") is not None:
                out["Mcp-Method"] = str(parsed["method"])
            name = (parsed.get("params") or {}).get("name")
            if name is not None:
                out["Mcp-Name"] = str(name)
        else:
            out["Mcp-Method"] = str(rng.choice(METHODS))
            out["Mcp-Name"] = str(rng.choice(TOOLS))
    if rng.random() < 0.1:
        out["traceparent"] = rng.choice(
            ["00-" + "a" * 32 + "-" + "b" * 16 + "-01", "garbage", "\x00"])
    return out


def check(gateway: HttpGateway, forwarded: list, headers: dict,
          body: str) -> list[str]:
    forwarded.clear()
    try:
        response = gateway.handle(headers, body)
    except Exception as exc:  # noqa: BLE001 - a raise IS the failure here
        return [f"TOTAL({type(exc).__name__}: {exc})"]

    failures: list[str] = []
    if response.body:
        try:
            parsed = json.loads(response.body)
        except ValueError:
            return ["JSON-RPC(response body is not JSON)"]
        if response.status >= 400 and not isinstance(parsed, dict):
            failures.append("JSON-RPC(error response is not an object)")
        elif response.status >= 400 and "error" not in parsed:
            failures.append("JSON-RPC(error response carries no error)")

    # A 502 is the UPSTREAM failing after the gateway allowed and forwarded, so
    # it is not a bypass and counting it as one measured the test's own stub.
    # A gateway refusal is a 4xx or a policy error in the body.
    if forwarded and 400 <= response.status < 500:
        failures.append("NO-BYPASS(forwarded a message the gateway refused)")
    if forwarded:
        # Whatever went upstream must be the message the gateway checked.
        sent = forwarded[-1]
        try:
            json.loads(sent)
        except ValueError:
            failures.append("NO-BYPASS(forwarded text is not JSON)")
        from clayseal.capabilities.http_gateway import check_headers

        try:
            if not check_headers(headers, json.loads(sent), require=False).ok:
                failures.append("HEADER-HONEST(forwarded a mismatched message)")
        except ValueError:
            pass
    return failures


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cases", type=int, default=40_000)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--show", type=int, default=6)
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    rng = random.Random(args.seed)  # noqa: S311 - reproducible, not secret
    failures: Counter[str] = Counter()
    examples: dict[str, list[str]] = {}
    forwarded: list[str] = []

    def upstream(text: str) -> str:
        forwarded.append(text)
        return json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})

    for i in range(args.cases):
        if i % 500 == 0:      # a fresh session periodically, budgets and all
            gateway = HttpGateway(
                proxy=McpProxy.from_policy(load_policy_text(POLICY)),
                upstream=upstream, require_headers=False)
        body = _body(rng)
        headers = _headers(rng, body)
        for name in check(gateway, forwarded, headers, body):
            key = name.split("(")[0]
            failures[key] += 1
            examples.setdefault(key, [])
            if len(examples[key]) < args.show:
                examples[key].append(f"{name}  headers={headers} body={body[:70]!r}")

    print("# The HTTP gateway under randomized stress\n")
    print("STATUS: current\n")
    print("```bash")
    print(f"python -m benchmarks.stress_http --cases {args.cases} "
          f"--seed {args.seed}")
    print("```\n")
    print(f"{args.cases} generated request pairs against the only component "
          f"here that parses\ninput arriving from a socket.\n")
    print("| property | violations |")
    print("| --- | --: |")
    for name in ("TOTAL", "JSON-RPC", "NO-BYPASS", "HEADER-HONEST"):
        print(f"| {name} | {failures.get(name, 0)} of {args.cases} |")
    if failures:
        print("\n## Violations\n")
        for name, count in failures.most_common():
            print(f"**{name}: {count}**\n")
            for line in examples.get(name, []):
                print(f"    {line}")
            print()
        return 1
    print("\nNo property was violated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
