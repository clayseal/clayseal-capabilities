"""Streamable HTTP, and the bypass the transport's own headers create.

SEP-2243 adds `Mcp-Method` and `Mcp-Name` so that gateways can route "without
inspecting the body". The spec puts the duty to check them against the body on
SERVERS, with the body as source of truth and `-32020` on mismatch. A security
gateway in front is exactly the intermediary invited to skip the body, and one
that authorizes `Mcp-Method: tools/list` while the server executes a
`tools/call` for a money-moving tool has approved an operation that never ran.

That is the duplicate-JSON-key differential this repository already closed,
promoted to the transport layer and written into the protocol.
"""
from __future__ import annotations

import json

import pytest

from clayseal.capabilities.http_gateway import (
    HEADER_MISMATCH,
    MCP_PROTOCOL_VERSION,
    HttpGateway,
    check_headers,
)
from clayseal.capabilities.mcp_proxy import POLICY_DENIED, McpProxy
from clayseal.capabilities.policy import load_policy_text

BASE = """
version: 1
goal: {id: ap, summary: Pay approved invoices}
profile: supervised
tools:
  allow: [pay_vendor, read_file]
  effects: {pay_vendor: transfer, read_file: read}
paths: {pathless: [pay_vendor, read_file]}
budgets:
  value:
    ceilings: {payments: "50000"}
    tracked: {pay_vendor: {arg: amount, budget: payments, identity: [invoice]}}
"""


def _document(path) -> str:
    return BASE + (f"deployment: {{stateless: true, principal: acct-9, "
                   f"ledger: {{path: {path}}}}}\n")


def _gateway(path, **kwargs) -> HttpGateway:
    policy = load_policy_text(_document(path))
    return HttpGateway(proxy=McpProxy.from_policy(policy), **kwargs)


def _call(tool: str, args: dict, rid: int = 1) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                       "params": {"name": tool, "arguments": args}})


def _headers(method="tools/call", name="pay_vendor") -> dict:
    out = {}
    if method is not None:
        out["Mcp-Method"] = method
    if name is not None:
        out["Mcp-Name"] = name
    return out


def _error(response) -> dict:
    return json.loads(response.body).get("error", {})


# ------------------------------------------------- the header is not the call ---
def test_a_header_naming_another_method_is_refused():
    body = _call("pay_vendor", {"amount": "99999", "invoice": "X"})
    check = check_headers(_headers(method="tools/list"), json.loads(body))
    assert not check.ok
    assert "source of truth" in check.reason


def test_a_header_naming_another_tool_is_refused():
    body = _call("pay_vendor", {"amount": "1", "invoice": "X"})
    check = check_headers(_headers(name="read_file"), json.loads(body))
    assert not check.ok


def test_agreeing_headers_pass():
    body = _call("pay_vendor", {"amount": "1", "invoice": "X"})
    assert check_headers(_headers(), json.loads(body)).ok


def test_a_missing_header_is_refused_by_default():
    """The spec requires it, and a gateway that cannot see what it is routing
    is not routing it."""
    body = _call("pay_vendor", {"amount": "1", "invoice": "X"})
    assert not check_headers({}, json.loads(body)).ok
    assert check_headers({}, json.loads(body), require=False).ok


def test_headers_cannot_describe_a_batch():
    """One pair of headers cannot describe several messages, and choosing a
    member to believe is how a gateway approves the wrong one."""
    body = [json.loads(_call("pay_vendor", {"amount": "1", "invoice": "X"}))]
    assert not check_headers(_headers(), body).ok
    assert check_headers({}, body).ok


@pytest.mark.parametrize("headers", [
    {"Mcp-Method": "tools/list", "Mcp-Name": "pay_vendor"},
    {"Mcp-Method": "tools/call", "Mcp-Name": "read_file"},
    {},
])
def test_the_gateway_refuses_before_authorizing_anything(tmp_path, headers):
    gateway = _gateway(tmp_path / "l.jsonl")
    response = gateway.handle(
        headers, _call("pay_vendor", {"amount": "99999", "invoice": "X"}))
    assert response.status == 400
    assert _error(response)["code"] == HEADER_MISMATCH
    assert gateway.transport_refusals == 1
    assert response.headers["MCP-Protocol-Version"] == MCP_PROTOCOL_VERSION


def test_the_body_is_what_gets_authorized(tmp_path):
    """Agreeing headers do not exempt the body from the policy."""
    gateway = _gateway(tmp_path / "l.jsonl")
    over = gateway.handle(_headers(),
                          _call("pay_vendor", {"amount": "99999", "invoice": "X"}))
    assert over.status == 200
    assert _error(over)["code"] == POLICY_DENIED
    assert "value_budget_exceeded" in _error(over)["message"]


# ------------------------------------------------ statelessness, end to end ---
def test_the_ceiling_holds_across_two_independent_gateways(tmp_path):
    """Two instances, as a load balancer would choose. Nothing is shared but
    the ledger on disk."""
    ledger = tmp_path / "l.jsonl"
    first = _gateway(ledger)
    assert first.handle(
        _headers(), _call("pay_vendor", {"amount": "30000", "invoice": "A"})
    ).status == 200

    second = _gateway(ledger)
    over = second.handle(
        _headers(), _call("pay_vendor", {"amount": "30000", "invoice": "B"}, 2))
    assert "value_budget_exceeded" in _error(over)["message"]

    duplicate = second.handle(
        _headers(), _call("pay_vendor", {"amount": "10", "invoice": "A"}, 3))
    assert "value_budget_duplicate_effect" in _error(duplicate)["message"]


def test_readiness_says_which_tiers_cannot_run(tmp_path):
    """An operator reading a quiet log cannot tell a tier that found nothing
    from a tier that never ran."""
    ready = _gateway(tmp_path / "l.jsonl").readiness()
    assert ready["protocol_version"] == MCP_PROTOCOL_VERSION
    assert ready["floor"] == "live"
    assert "principal ledger" in ready["aggregates"]


def test_a_session_scoped_deployment_says_its_aggregates_are_inert():
    gateway = HttpGateway(proxy=McpProxy.from_policy(load_policy_text(BASE)))
    assert "INERT" in gateway.readiness()["aggregates"]


def test_an_unreadable_body_is_a_refusal_not_a_crash(tmp_path):
    gateway = _gateway(tmp_path / "l.jsonl")
    for body in ("{not json", "", '{"jsonrpc":"2.0","id":1,"id":2}'):
        response = gateway.handle(_headers(), body)
        assert response.status == 400, body
    assert gateway.transport_refusals == 3


def test_an_upstream_failure_is_502_and_not_an_allow(tmp_path):
    def explode(_body):
        raise OSError("connection refused")

    gateway = _gateway(tmp_path / "l.jsonl", upstream=explode)
    response = gateway.handle(
        _headers(), _call("pay_vendor", {"amount": "10", "invoice": "Z"}))
    assert response.status == 502
    assert "upstream unavailable" in _error(response)["message"]


# ------------------------------------ an upstream must not be able to stall ---
def _timed(gateway, calls=3) -> float:
    import time

    start = time.perf_counter()
    for i in range(calls):
        gateway.handle(_headers(), _call("pay_vendor", {"amount": "1"}, i))
    return time.perf_counter() - start


@pytest.mark.parametrize("upstream,label", [
    (lambda text: json.dumps({"jsonrpc": "2.0", "id": 999, "result": {}}),
     "echoes a wrong id"),
    (lambda text: (_ for _ in ()).throw(OSError("down")), "raises"),
    (lambda text: "not json at all", "returns junk"),
    (lambda text: "", "returns nothing"),
])
def test_no_upstream_behaviour_can_stall_the_gateway(tmp_path, upstream, label):
    """A mismatched id once cost 15 seconds on every LATER effectful call.

    `McpProxy` correlates a request with its reply by JSON-RPC id, which over
    stdio is the only correlation there is. Over HTTP the request IS the
    correlation and the id is a formality the server may get wrong; when it did,
    `serialize_effects` waited out the full `settle_timeout`. Three calls took
    30.02 seconds against 0.00 with a correct id, which is an availability
    failure a non-compliant upstream triggers for free.
    """
    gateway = _gateway(tmp_path / "l.jsonl", upstream=upstream)
    assert _timed(gateway) < 2.0, label


def test_a_correct_upstream_is_unaffected(tmp_path):
    def echo(text):
        return json.dumps({"jsonrpc": "2.0", "id": json.loads(text).get("id"),
                           "result": {}})

    assert _timed(_gateway(tmp_path / "l.jsonl", upstream=echo)) < 2.0


def test_settle_is_idempotent_and_safe_on_an_unknown_id(tmp_path):
    """The HTTP path calls it in a `finally`, so it runs on paths that never
    forwarded anything."""
    gateway = _gateway(tmp_path / "l.jsonl")
    gateway.proxy.settle(None)
    gateway.proxy.settle("never-seen")
    gateway.proxy.settle(None)


def test_the_gateway_holds_under_randomized_stress(tmp_path):
    """A smaller run of `benchmarks.stress_http`, so CI exercises the boundary.

    The full pass is 40,000 request pairs. This is the regression guard on the
    only component here that parses input arriving from a socket.
    """
    import random

    from benchmarks.stress_http import _body, check
    from benchmarks.stress_http import _headers as _fuzz_headers

    forwarded: list[str] = []

    def upstream(text: str) -> str:
        forwarded.append(text)
        try:
            request_id = json.loads(text).get("id")
        except (ValueError, AttributeError):
            request_id = None
        return json.dumps({"jsonrpc": "2.0", "id": request_id,
                           "result": {"ok": True}})

    gateway = _gateway(tmp_path / "l.jsonl", upstream=upstream,
                       require_headers=False)
    rng = random.Random(11)  # noqa: S311 - reproducible sweep, not a secret
    violations: list[str] = []
    for _ in range(3000):
        body = _body(rng)
        violations.extend(check(gateway, forwarded, _fuzz_headers(rng, body), body))
    assert not violations, violations[:6]
