"""The join key between a durable receipt and the trace that produced it.

`DecisionLog` was internally verifiable and externally unjoinable: an enterprise
holding an incident had a trace of what its agent did and a receipt of what this
gateway decided, and nothing lining the two up. That was survivable while a
session existed, by convention. MCP 2026-07-28 removes the session, and W3C
Trace Context is what replaces it for audit.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from agentauth.capabilities.decision_log import DecisionLog
from agentauth.capabilities.http_gateway import HttpGateway
from agentauth.capabilities.mcp_proxy import McpProxy
from agentauth.capabilities.policy import load_policy_text
from agentauth.capabilities.trace import MAX_TRACESTATE, TraceContext

VALID = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


# ------------------------------------------------------------- parsing -----
def test_a_valid_header_parses():
    context = TraceContext.parse(VALID)
    assert context.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert context.traceparent == VALID


@pytest.mark.parametrize("header", [
    "", "nonsense", None, 12345,
    VALID.upper(),                                    # hex must be lower case
    "ff-" + VALID[3:],                                # version ff is forbidden
    "00-" + "0" * 32 + "-00f067aa0ba902b7-01",        # all-zero trace id
    "00-4bf92f3577b34da6a3ce929d0e0e4736-" + "0" * 16 + "-01",
    VALID[:-1], VALID + "-extra",                     # wrong widths
])
def test_anything_that_is_not_a_header_is_dropped(header):
    """A record with no trace is honest; one carrying a trace id nobody can
    join to is a field that looks like evidence and is not."""
    assert TraceContext.parse(header) is None


def test_an_oversized_tracestate_is_dropped_not_stored():
    """The only unbounded field in the header set, and it lands in every
    record."""
    assert TraceContext.parse(VALID, "x" * (MAX_TRACESTATE + 1)).tracestate == ""
    assert TraceContext.parse(VALID, "acme=1").tracestate == "acme=1"


def test_headers_are_read_case_insensitively():
    assert TraceContext.from_headers({"TraceParent": VALID}).trace_id


# ----------------------------------------------------- the hash chain ------
def test_a_record_without_a_trace_hashes_exactly_as_it_did_before():
    """The chain IS the evidence. Re-hashing every historical record to add an
    optional field would invalidate the thing the field is there to serve."""
    log = DecisionLog()
    record = log.append(query_id="q", tool="t", resource="r", action_verb="read",
                        arguments_hash="h", outcome="allow", layer="-",
                        reasons=())
    assert "trace" not in record.body()


def test_a_record_with_a_trace_carries_the_join_key_and_still_chains():
    log = DecisionLog()
    log.append(query_id="q", tool="t", resource="r", action_verb="read",
               arguments_hash="h", outcome="allow", layer="-", reasons=())
    stamped = log.append(query_id="q", tool="t", resource="r",
                         action_verb="read", arguments_hash="h",
                         outcome="allow", layer="-", reasons=(),
                         trace=TraceContext.parse(VALID).to_dict())
    assert stamped.body()["trace"]["trace_id"].startswith("4bf92f")
    assert log.verify() == (True, None)


# ------------------------------------------------- through the transport ---
def _gateway():
    ledger = Path(tempfile.mkdtemp()) / "l.jsonl"
    document = f"""
version: 1
goal: {{id: ap, summary: Pay invoices}}
profile: supervised
tools: {{allow: [pay_vendor], effects: {{pay_vendor: transfer}}}}
paths: {{pathless: [pay_vendor]}}
budgets:
  value:
    ceilings: {{payments: "50000"}}
    tracked: {{pay_vendor: {{arg: amount, budget: payments, identity: [invoice]}}}}
deployment: {{stateless: true, principal: acct-9, ledger: {{path: {ledger}}}}}
"""
    return HttpGateway(proxy=McpProxy.from_policy(load_policy_text(document)))


def _body(request_id: int, invoice: str) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
                       "params": {"name": "pay_vendor",
                                  "arguments": {"amount": "100",
                                                "invoice": invoice}}})


def test_the_gateway_reads_the_header_per_request():
    """Per REQUEST, because that is the granularity a stateless transport has."""
    gateway = _gateway()
    log = gateway.proxy.gateway.broker.decision_log
    gateway.handle({"Mcp-Method": "tools/call", "Mcp-Name": "pay_vendor",
                    "traceparent": VALID, "tracestate": "acme=7"},
                   _body(1, "A"))
    trace = log.records()[-1]["trace"]
    assert trace["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert trace["tracestate"] == "acme=7"


def test_a_malformed_header_leaves_the_receipt_honest():
    gateway = _gateway()
    log = gateway.proxy.gateway.broker.decision_log
    gateway.handle({"Mcp-Method": "tools/call", "Mcp-Name": "pay_vendor",
                    "traceparent": "garbage"}, _body(1, "A"))
    assert "trace" not in log.records()[-1]
    assert log.verify() == (True, None)


def test_the_in_process_adapter_takes_one_too():
    from agentauth.capabilities.guardrail import Guardrail

    guard = Guardrail.from_policy(load_policy_text(
        "version: 1\ngoal: {id: g, summary: s}\n"
        "tools: {allow: [ping], effects: {ping: read}}\n"
        "paths: {pathless: [ping]}\n"))
    guard.trace(VALID)
    assert guard.stack.broker.trace.trace_id.startswith("4bf92f")
    guard.trace("garbage")
    assert guard.stack.broker.trace is None
