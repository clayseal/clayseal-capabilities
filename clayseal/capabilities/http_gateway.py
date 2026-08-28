"""MCP over Streamable HTTP, which is the transport a deployment actually uses.

`mcp_proxy` speaks stdio. Stdio is local, single-client, and the process
boundary is the session boundary, which is why that module could say "one proxy
process is one session" and be right. MCP 2026-07-28 recommends **Streamable
HTTP** for anything remote and removes the `initialize` handshake and the
`Mcp-Session-Id` header entirely, so that any instance can serve any request
with no sticky routing.

This is the front end for that world. It does not re-implement the decision
path: `McpProxy.handle_client_message` already refuses duplicate JSON keys, near
-match method names, oversized batches and unresolvable paths, and every one of
those was a measured bypass. This adds the transport and the two things the
transport brings with it.

THE HEADER IS NOT THE DECISION

SEP-2243 adds `Mcp-Method` and `Mcp-Name` so that "load balancers, gateways, and
rate-limiters can route on the operation without inspecting the body". The spec
is careful about the ambiguity that creates: the **body is the source of truth**,
a server MUST check the headers against it, and a mismatch is rejected with
`-32020`.

Note who that duty falls on. Servers validate. A security gateway placed in
front is exactly the intermediary being invited to skip the body, and one that
authorizes `Mcp-Method: tools/list` while the server executes a `tools/call` for
a money-moving tool has approved an operation that never ran and let the one
that ran go unchecked. That is the duplicate-JSON-key differential this
repository already closed, promoted to the transport layer and written into the
protocol.

So: **the body is authorized, always.** Headers are checked for agreement and
never consulted for a decision, and a disagreement is a refusal rather than a
preference.

WHAT IS LIVE WITHOUT A SESSION, AND WHAT IS NOT

This is the part a deployment has to be told rather than left to discover.

**The floor is live.** Task scope, protected zones, egress, tool admissibility
and the conditional withdrawals are all pure functions of one action and the
grant. They neither know nor care that the request arrived alone.

**Aggregates are live only against a principal ledger.** A per-session ceiling
counts over nothing here, so `readiness()` reports it and the policy compiler
refuses the combination outright.

**The trajectory tiers are NOT live.** The intent envelope, the CUSUM drift
detector and the behavioural detector all read a sequence, and a stateless
request has no sequence to read. They are reported inert rather than run against
a trajectory of length one, because a tier that cannot see what it is built to
see should say so instead of returning a confident verdict about nothing.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from clayseal.capabilities.mcp_proxy import TOOL_CALL, McpProxy, _strict_loads
from clayseal.capabilities.trace import TraceContext

#: The specification this front end implements.
MCP_PROTOCOL_VERSION = "2026-07-28"

#: SEP-2243's code for a routing header that disagrees with the body.
HEADER_MISMATCH = -32020
#: JSON-RPC's own codes, for a body this gateway cannot read at all.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600

#: Tiers that read a sequence. Named here so `readiness` can report them inert
#: rather than leaving an operator to infer it from a quiet log.
TRAJECTORY_TIERS = ("intent_envelope", "detector")


def _header(headers: Any, name: str) -> str | None:
    """Case-insensitive lookup that works on a dict or a `email.message`."""
    getter = getattr(headers, "get", None)
    if getter is None:
        return None
    value = getter(name)
    if value is None:
        lowered = {str(k).lower(): v for k, v in dict(headers).items()}
        value = lowered.get(name.lower())
    return None if value is None else str(value)


@dataclass
class HeaderCheck:
    ok: bool
    reason: str = ""


def check_headers(headers: Any, body: Any, *, require: bool = True) -> HeaderCheck:
    """Do the routing headers describe the operation the body actually asks for?

    The body is the authority. This never resolves a disagreement in the
    header's favour and never uses a header to decide anything; it only refuses
    when the two do not match, which is what stops a gateway approving one
    operation while the server runs another.
    """
    method_header = _header(headers, "Mcp-Method")
    name_header = _header(headers, "Mcp-Name")

    if isinstance(body, list):
        # A batch cannot be described by one pair of headers. Rather than pick a
        # member to believe, refuse: the whole value of the headers is that they
        # describe the request, and here they cannot.
        if method_header or name_header:
            return HeaderCheck(False,
                               "routing headers cannot describe a batch, and a "
                               "gateway must not choose which member they mean")
        return HeaderCheck(True)

    if not isinstance(body, dict):
        return HeaderCheck(False, "body is not a JSON-RPC message")

    body_method = body.get("method")
    if method_header is None:
        if require:
            return HeaderCheck(
                False,
                f"Mcp-Method is required by MCP {MCP_PROTOCOL_VERSION} and is "
                f"absent. A gateway that cannot see what it is routing is not "
                f"routing it")
        return HeaderCheck(True)
    if body_method is None or str(method_header) != str(body_method):
        return HeaderCheck(
            False,
            f"Mcp-Method is {method_header!r} and the body asks for "
            f"{body_method!r}. The body is the source of truth and the "
            f"disagreement is refused rather than resolved")

    if str(body_method) == TOOL_CALL:
        params = body.get("params")
        tool = params.get("name") if isinstance(params, dict) else None
        if name_header is None:
            if require:
                return HeaderCheck(
                    False, f"Mcp-Name is required for {TOOL_CALL} and is absent")
        elif tool is None or str(name_header) != str(tool):
            return HeaderCheck(
                False,
                f"Mcp-Name is {name_header!r} and the body calls {tool!r}")
    return HeaderCheck(True)


@dataclass
class HttpResponse:
    status: int
    body: str
    headers: dict[str, str] = field(default_factory=dict)


def _error(code: int, message: str, request_id: Any = None) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": request_id,
                       "error": {"code": code, "message": message}})


@dataclass
class HttpGateway:
    """One MCP request in, one authorization decision, one response out.

    Holds an `McpProxy` for the decision path rather than reimplementing it.
    `upstream` is a callable taking the forwarded JSON text and returning the
    server's reply; leaving it None makes this a decision-only gateway, which is
    what the tests drive and what a deployment fronting its own handler wants.
    """

    proxy: McpProxy
    upstream: Any = None
    require_headers: bool = True
    #: Requests refused before any authorization ran, because the transport
    #: itself was wrong. Counted separately: a spike here is somebody probing
    #: the header/body seam, not an agent misbehaving.
    transport_refusals: int = 0

    def readiness(self) -> dict[str, Any]:
        """What is live in this deployment, and what cannot be.

        An operator reading a quiet log cannot tell a tier that found nothing
        from a tier that never ran. This is the difference, stated.
        """
        broker = getattr(self.proxy.gateway, "broker", None)
        inert = [name for name in TRAJECTORY_TIERS
                 if getattr(broker, name, None) is not None]
        budget = getattr(broker, "value_budget", None)
        principal_scoped = type(budget).__name__ == "PrincipalBudgetView"
        return {
            "protocol_version": MCP_PROTOCOL_VERSION,
            "floor": "live",
            "aggregates": "live (principal ledger)" if principal_scoped
            else "INERT: a per-session ceiling counts over nothing here",
            "trajectory_tiers": (
                f"INERT: {', '.join(inert)} read a sequence and a stateless "
                f"request has none" if inert else "not configured"),
            "transport_refusals": self.transport_refusals,
            "trace_context": "read per request from `traceparent`",
        }

    def handle(self, headers: Any, body: str) -> HttpResponse:
        """Decide one HTTP request. Never raises to the server loop."""
        try:
            parsed = _strict_loads(body)
        except Exception as exc:  # noqa: BLE001 - a bad body is a refusal
            self.transport_refusals += 1
            return HttpResponse(400, _error(PARSE_ERROR, str(exc)))

        # The join key between this gateway's receipts and the caller's trace.
        # Read per REQUEST, because that is the granularity a stateless
        # transport has: there is no session to carry one.
        broker = getattr(self.proxy.gateway, "broker", None)
        if broker is not None:
            broker.trace = TraceContext.from_headers(headers)

        check = check_headers(headers, parsed, require=self.require_headers)
        if not check.ok:
            self.transport_refusals += 1
            request_id = parsed.get("id") if isinstance(parsed, dict) else None
            return HttpResponse(
                400, _error(HEADER_MISMATCH, check.reason, request_id),
                {"MCP-Protocol-Version": MCP_PROTOCOL_VERSION})

        # The body, and only the body, reaches the decision path.
        forward, refusal = self.proxy.handle_client_message(body)
        if refusal is not None:
            return HttpResponse(200, refusal,
                                {"MCP-Protocol-Version": MCP_PROTOCOL_VERSION})
        if forward is None:
            return HttpResponse(204, "",
                                {"MCP-Protocol-Version": MCP_PROTOCOL_VERSION})
        if self.upstream is None:
            return HttpResponse(200, forward,
                                {"MCP-Protocol-Version": MCP_PROTOCOL_VERSION})
        request_id = parsed.get("id") if isinstance(parsed, dict) else None
        try:
            reply = self.upstream(forward)
        except Exception as exc:  # noqa: BLE001 - an upstream failure is not ours
            # The exchange is over even though it failed, so release it. Leaving
            # it outstanding makes one upstream error cost `settle_timeout` on
            # the NEXT call as well.
            self.proxy.settle(request_id)
            return HttpResponse(
                502, _error(INVALID_REQUEST, f"upstream unavailable: {exc}"))
        try:
            return HttpResponse(200, self.proxy.handle_server_message(reply),
                                {"MCP-Protocol-Version": MCP_PROTOCOL_VERSION})
        finally:
            # One exchange per request over HTTP, so the request IS the
            # correlation and the id the server echoed is a formality it may get
            # wrong. Measured before this: a mismatched id stalled every later
            # effectful call for 15 seconds.
            self.proxy.settle(request_id)


# --------------------------------------------------------------------------- #
# A server, from the standard library only.
# --------------------------------------------------------------------------- #

def urllib_upstream(url: str, *, timeout: float = 30.0):
    """Forward to a Streamable HTTP MCP server. `urllib`, so no new dependency.

    The routing headers are regenerated from the FORWARDED body rather than
    copied from the client's request. Copying them would pass an attacker's
    header through to a server that trusts it, which is the disagreement this
    gateway exists to refuse, handed on one hop further.
    """
    import urllib.request

    def send(body: str) -> str:
        parsed = json.loads(body)
        headers = {"Content-Type": "application/json",
                   "MCP-Protocol-Version": MCP_PROTOCOL_VERSION}
        if isinstance(parsed, dict) and parsed.get("method"):
            headers["Mcp-Method"] = str(parsed["method"])
            params = parsed.get("params")
            if isinstance(params, dict) and params.get("name"):
                headers["Mcp-Name"] = str(params["name"])
        request = urllib.request.Request(  # noqa: S310 - the operator's own URL
            url, data=body.encode(), headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.read().decode()

    return send


def serve(gateway: HttpGateway, *, host: str = "127.0.0.1", port: int = 8900,
          path: str = "/mcp", log: Any = None) -> Any:
    """Run `gateway` over HTTP. Returns the server so a caller can shut it down.

    `ThreadingHTTPServer` because the transport is stateless and requests are
    independent; the broker holds its own lock and the ledger its own
    transaction, so two requests arriving together serialize where they must.
    """
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: Any) -> None:
            if log is not None:
                log(fmt % args)

        def _write(self, response: HttpResponse) -> None:
            payload = response.body.encode()
            self.send_response(response.status)
            for key, value in response.headers.items():
                self.send_header(key, value)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if payload:
                self.wfile.write(payload)

        def do_GET(self) -> None:  # the stdlib spells it this way
            if self.path.rstrip("/") == path.rstrip("/") + "/readiness":
                self._write(HttpResponse(200, json.dumps(gateway.readiness())))
                return
            self._write(HttpResponse(404, _error(INVALID_REQUEST, "not found")))

        def do_POST(self) -> None:  # the stdlib spells it this way
            if self.path.rstrip("/") != path.rstrip("/"):
                self._write(HttpResponse(404, _error(INVALID_REQUEST, "not found")))
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                self._write(HttpResponse(400, _error(PARSE_ERROR, "bad length")))
                return
            if length > MAX_BODY_BYTES:
                gateway.transport_refusals += 1
                self._write(HttpResponse(
                    413, _error(INVALID_REQUEST,
                                f"body over {MAX_BODY_BYTES} bytes")))
                return
            body = self.rfile.read(length).decode("utf-8", "replace")
            self._write(gateway.handle(self.headers, body))

    server = ThreadingHTTPServer((host, port), Handler)
    return server


#: A body larger than this is refused before it is parsed. An authorization
#: decision is made per call and no legitimate one is megabytes; reading an
#: unbounded body into memory is a denial of service anyone can trigger.
MAX_BODY_BYTES = 4 * 1024 * 1024
