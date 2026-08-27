"""Every surface an integrator reaches for, exercised rather than described.

These are cheap end-to-end checks over the documented integration points. They
exist because a broken integration is invisible to the corpora: nothing in the
benchmark harness speaks MCP over HTTP, emits OCSF, or wraps a framework's
tools.
"""
from __future__ import annotations

import json

import pytest

REFUND_POLICY = "examples/refund.yaml"


def test_wrapping_tools_preserves_what_a_framework_introspects():
    """LangGraph, the OpenAI Agents SDK and CrewAI all read these."""
    import inspect

    from clayseal.capabilities import Guardrail, Refused

    def issue_refund(invoice, amount):
        """Refund one invoice."""
        return f"ok {invoice}"

    guard = Guardrail.from_policy_file(REFUND_POLICY)
    wrapped = guard.wrap_all({"issue_refund": issue_refund})["issue_refund"]

    assert wrapped.__name__ == "issue_refund"
    assert wrapped.__doc__ == issue_refund.__doc__
    assert list(inspect.signature(wrapped).parameters) == ["invoice", "amount"]

    assert wrapped(invoice="INV-1", amount=900.0)
    with pytest.raises(Refused):
        wrapped(invoice="INV-2", amount=900.0)


def test_the_mcp_proxy_withholds_and_refuses():
    from clayseal.capabilities.mcp_proxy import McpProxy
    from clayseal.capabilities.policy import load_policy

    proxy = McpProxy.from_policy(load_policy(REFUND_POLICY))
    listing = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
        {"name": "issue_refund"}, {"name": "wire_funds"}]}})
    advertised = [t["name"] for t in
                  json.loads(proxy.handle_server_message(listing))["result"]["tools"]]
    assert "wire_funds" not in advertised, "an ungranted tool was advertised"

    call = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                       "params": {"name": "wire_funds", "arguments": {}}})
    to_server, to_client = proxy.handle_client_message(call)
    assert to_server is None, "an ungranted call was forwarded upstream"
    assert "error" in json.loads(to_client)


def test_the_http_gateway_speaks_the_current_protocol():
    from clayseal.capabilities.http_gateway import (
        MCP_PROTOCOL_VERSION,
        HttpGateway,
    )
    from clayseal.capabilities.mcp_proxy import McpProxy
    from clayseal.capabilities.policy import load_policy

    gateway = HttpGateway(proxy=McpProxy.from_policy(load_policy(REFUND_POLICY)))
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "wire_funds", "arguments": {}}})
    headers = {"MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
               "Mcp-Method": "tools/call", "Mcp-Name": "wire_funds"}
    assert "error" in json.loads(gateway.handle(headers, body).body)

    # SEP-2243: the body is the source of truth, and a header that disagrees
    # with it is refused rather than believed.
    lying = dict(headers, **{"Mcp-Method": "tools/list"})
    error = json.loads(gateway.handle(lying, body).body)["error"]
    assert error["code"] == -32020, error

    assert "protocol_version" in gateway.readiness()


def test_a_decision_renders_as_ocsf_api_activity():
    from clayseal.capabilities.decision_log import DecisionRecord
    from clayseal.capabilities.decision_sinks import to_ocsf

    record = DecisionRecord(
        seq=1, receipt_id="r", created_at="2026-08-26T00:00:00Z", query_id="q",
        tool="issue_refund", resource="mcp:tool:issue_refund",
        action_verb="transfer", arguments_hash="sha256:x", outcome="deny",
        layer="floor", reasons=("value_budget_exceeded",), anomaly_score=None,
        prev_hash="")
    event = to_ocsf(record.body())
    assert event["class_uid"] == 6003, "not OCSF API Activity"
    for field in ("category_uid", "activity_id", "severity_id", "time",
                  "metadata"):
        assert field in event, f"OCSF event is missing {field}"


def test_trace_context_joins_a_receipt_to_the_caller_s_span():
    from clayseal.capabilities.trace import TraceContext

    parsed = TraceContext.parse(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
    assert parsed and parsed.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert TraceContext.parse("not-a-traceparent") is None


def test_a_document_becomes_a_policy_the_loader_accepts():
    from clayseal.capabilities.policy import load_policy_text
    from clayseal.capabilities.policy_draft import extract, to_yaml

    draft = extract("Payments over $10,000 require approval.",
                    tools=["pay_vendor"])
    assert draft.rules, "the canonical delegation-of-authority sentence"
    rendered = to_yaml(draft, goal_id="g", tools=["pay_vendor"])
    assert load_policy_text(rendered).allowed_tools == {"pay_vendor"}
