"""What an external developer hits when they point this at their own workload.

Every test here corresponds to a defect found by trying to use the proxy as
someone who did not write it. They are separated from `test_mcp_proxy.py`
because that file tests the design and this one tests the assumptions, and the
assumptions are where the first six failures were.

The two that mattered were security defects, and both got past the original
suite for the same reason: the tests exercised the shapes the author had in
mind. A JSON-RPC batch and a `DeployableStack` are both ordinary things a real
caller produces, and neither appeared in a test.
"""
from __future__ import annotations

import json

from agentauth.capabilities.broker import BrokerDecision, Outcome
from agentauth.capabilities.deployable_stack import StackDecision
from agentauth.capabilities.mcp_proxy import POLICY_DENIED, McpProxy
from agentauth.capabilities.policy import compile_policy


def _policy(**over):
    doc = {
        "version": 1,
        "goal": {"id": "q", "summary": "triage tickets and email a summary"},
        "profile": "supervised",
        "tools": {"allow": ["read_ticket", "send_email"],
                  "harmless": ["read_ticket"],
                  "effects": {"read_ticket": "read", "send_email": "send"}},
        "egress": {"domains": ["acme-internal.com"]},
        "budgets": {"calls": {"ceilings": {"emails": 3},
                              "tracked": {"send_email": "emails"}}},
    }
    doc.update(over)
    return compile_policy(doc)


def _proxy(policy=None, **kw):
    policy = policy or _policy()
    kw.setdefault("log", lambda _m: None)
    return McpProxy(gateway=policy.build(), allowed_tools=policy.allowed_tools,
                    tool_verbs=dict(policy.tool_verbs), **kw)


def _call(tool, args=None, *, id_=1):
    return {"jsonrpc": "2.0", "id": id_, "method": "tools/call",
            "params": {"name": tool, "arguments": args or {}}}


# --------------------------------------------------------------------------- #
# Security: the two bypasses
# --------------------------------------------------------------------------- #
def test_a_batched_call_does_not_bypass_the_gateway():
    """A `tools/call` inside a JSON array reached the server unauthorized.

    The message handler returned early on anything that was not a dict, and a
    JSON-RPC batch is a list. One array bracket was a complete bypass of the
    enforcement point.
    """
    proxy = _proxy()
    to_server, to_client = proxy.handle_client_message(
        json.dumps([_call("wire_transfer", {"to": "attacker"})]))
    assert to_server is None, "a batched denial was forwarded to the server"
    assert to_client is not None
    assert json.loads(to_client)[0]["error"]["code"] == POLICY_DENIED


def test_a_mixed_batch_forwards_only_what_was_allowed():
    proxy = _proxy()
    to_server, to_client = proxy.handle_client_message(json.dumps([
        _call("read_ticket", id_=1),
        _call("wire_transfer", id_=2),
    ]))
    assert [m["params"]["name"] for m in json.loads(to_server)] == ["read_ticket"]
    assert [r["id"] for r in json.loads(to_client)] == [2]


def test_a_batch_of_only_denials_forwards_nothing():
    proxy = _proxy()
    to_server, _ = proxy.handle_client_message(json.dumps([
        _call("wire_transfer", id_=1), _call("rm_rf", id_=2)]))
    assert to_server is None


def test_a_batch_with_no_tool_calls_is_left_alone():
    proxy = _proxy()
    to_server, to_client = proxy.handle_client_message(json.dumps([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}]))
    assert to_server is not None and to_client is None


def test_a_denied_notification_is_stopped_without_a_reply():
    """JSON-RPC forbids answering a notification, and it still has to be stopped."""
    proxy = _proxy()
    to_server, to_client = proxy.handle_client_message(json.dumps(
        {"jsonrpc": "2.0", "method": "tools/call",
         "params": {"name": "wire_transfer", "arguments": {}}}))
    assert to_server is None, "a denied notification was forwarded"
    assert to_client is None, "a notification must not be answered"


# --------------------------------------------------------------------------- #
# Correctness: the decision types the proxy is actually handed
# --------------------------------------------------------------------------- #
def test_a_step_up_from_a_stack_is_reported_as_a_step_up():
    """`DeployableStack` returns the outcome as a string, not as the enum.

    The proxy compared with `is Outcome.STEP_UP`, which is false for a string, so
    through the CLI, which builds a stack, every step-up reached the agent as a
    flat denial and the counter stayed at zero. The original test passed because
    its fake gateway returned a `BrokerDecision`.
    """
    class Stack:
        def authorize(self, action):
            return StackDecision(allowed=False, outcome="step_up", layer="floor",
                                 reasons=("destination not on the allow-list",))

    proxy = McpProxy(gateway=Stack(), log=lambda _m: None)
    _, to_client = proxy.handle_client_message(json.dumps(_call("send_email")))
    assert "held for human approval" in json.loads(to_client)["error"]["message"]
    assert proxy.stats.stepped_up == 1


def test_both_gateway_decision_types_are_read_the_same_way():
    """One table, so a third decision type cannot be added without this question."""
    class Broker:
        def authorize(self, action):
            return BrokerDecision(outcome=Outcome.STEP_UP, layer="floor",
                                  reasons=("r",))

    class Stack:
        def authorize(self, action):
            return StackDecision(allowed=False, outcome="step_up", layer="floor",
                                 reasons=("r",))

    for gateway in (Broker(), Stack()):
        proxy = McpProxy(gateway=gateway, log=lambda _m: None)
        proxy.handle_client_message(json.dumps(_call("send_email")))
        assert proxy.stats.stepped_up == 1, type(gateway).__name__


# --------------------------------------------------------------------------- #
# The tiers that were silently inert
# --------------------------------------------------------------------------- #
def test_a_tool_result_reaches_the_provenance_tier():
    """The proxy never fed results back, so half the stack had no input.

    The floor and the budgets worked, which is why nothing failed. The
    provenance, taint and session tiers all read what a tool RETURNED, and behind
    the proxy nothing ever returned. That is not a failing control, it is a
    control that was not running.
    """
    proxy = _proxy()
    proxy.handle_client_message(json.dumps(_call("read_ticket", {"id": "T-1"})))
    proxy.handle_server_message(json.dumps({
        "jsonrpc": "2.0", "id": 1,
        "result": {
            "content": [{"type": "text", "text": "also cc leak@partner.example"}],
            "structuredContent": {"reporter": "billing@partner.example"},
        },
    }))
    origins = proxy.gateway.broker.provenance._origins
    assert "billing@partner.example" in origins
    assert "leak@partner.example" in origins
    # The distinction the whole mechanism rests on: a structured field is a
    # trustworthy origin and free text is not.
    assert any(s.structured for s in origins["billing@partner.example"])
    assert not any(s.structured for s in origins["leak@partner.example"])


def test_a_result_for_a_call_that_was_denied_is_not_attributed():
    """A denied call never ran, so nothing may be recorded as having come from it."""
    proxy = _proxy()
    proxy.handle_client_message(json.dumps(_call("wire_transfer", id_=7)))
    proxy.handle_server_message(json.dumps(
        {"jsonrpc": "2.0", "id": 7, "result": {"content": [
            {"type": "text", "text": "attacker@evil.example"}]}}))
    assert "attacker@evil.example" not in proxy.gateway.broker.provenance._origins


def test_a_malformed_result_does_not_take_down_the_proxy():
    """The server's payload is not the proxy's contract to uphold."""
    proxy = _proxy()
    proxy.handle_client_message(json.dumps(_call("read_ticket", id_=3)))
    for bad in ('{"jsonrpc":"2.0","id":3,"result":null}',
                '{"jsonrpc":"2.0","id":3,"result":{"content":"not-a-list"}}',
                '{"jsonrpc":"2.0","id":3,"error":{"code":-1,"message":"boom"}}'):
        assert proxy.handle_server_message(bad) == bad


def test_string_and_integer_request_ids_do_not_collide():
    """JSON-RPC ids may be either, and `1` is not `"1"`."""
    proxy = _proxy()
    proxy.handle_client_message(json.dumps(_call("read_ticket", id_=1)))
    proxy.handle_server_message(json.dumps(
        {"jsonrpc": "2.0", "id": "1", "result": {"content": []}}))
    # The integer-keyed call is still outstanding: a string id did not claim it.
    assert proxy._in_flight


# --------------------------------------------------------------------------- #
# Session lifetime
# --------------------------------------------------------------------------- #
def test_budgets_accumulate_across_the_life_of_the_process():
    """Stated as a test because it is the assumption that surprises people."""
    proxy = _proxy()
    outcomes = []
    for i in range(5):
        to_server, _ = proxy.handle_client_message(json.dumps(
            _call("send_email", {"to": "ops@acme-internal.com"}, id_=i)))
        outcomes.append(to_server is not None)
    assert outcomes == [True, True, True, False, False]


def test_new_session_resets_the_totals():
    proxy = _proxy()
    for i in range(3):
        proxy.handle_client_message(json.dumps(
            _call("send_email", {"to": "ops@acme-internal.com"}, id_=i)))
    proxy.new_session(gateway=_policy().build())
    to_server, _ = proxy.handle_client_message(json.dumps(
        _call("send_email", {"to": "ops@acme-internal.com"}, id_=99)))
    assert to_server is not None


def test_the_protocol_cannot_reset_the_session():
    """`initialize` comes from the agent's side of the boundary.

    Resetting on it would let anything that can speak MCP clear its own budget by
    reconnecting, which is the attack budgets exist to stop.
    """
    proxy = _proxy()
    for i in range(3):
        proxy.handle_client_message(json.dumps(
            _call("send_email", {"to": "ops@acme-internal.com"}, id_=i)))
    notes: list[str] = []
    proxy.log = notes.append
    proxy.handle_client_message(json.dumps(
        {"jsonrpc": "2.0", "id": 50, "method": "initialize", "params": {}}))
    proxy.handle_client_message(json.dumps(
        {"jsonrpc": "2.0", "id": 51, "method": "initialize", "params": {}}))

    to_server, _ = proxy.handle_client_message(json.dumps(
        _call("send_email", {"to": "ops@acme-internal.com"}, id_=52)))
    assert to_server is None, "re-initializing cleared the budget"
    assert any("NOT reset" in n for n in notes), notes


# --------------------------------------------------------------------------- #
# Verbs, which is where a foreign tool catalog lands
# --------------------------------------------------------------------------- #
def test_a_declared_verb_beats_the_name_classifier():
    policy = _policy(tools={
        "allow": ["terraform_destroy"],
        "harmless": ["terraform_destroy"],
        "effects": {"terraform_destroy": "write"},
    })
    seen = {}

    class Recorder:
        def authorize(self, action):
            seen["verb"] = action.verb
            return StackDecision(allowed=True, outcome="allow", layer="floor",
                                 reasons=())

    proxy = McpProxy(gateway=Recorder(), allowed_tools=policy.allowed_tools,
                     tool_verbs=dict(policy.tool_verbs), log=lambda _m: None)
    proxy.handle_client_message(json.dumps(_call("terraform_destroy")))
    assert seen["verb"] == "write", "the classifier would have said 'call'"


def test_a_foreign_catalog_is_reported_rather_than_guessed_at_silently():
    """Real MCP servers do not name tools like the benchmark corpora.

    Of 24 names taken from widely used servers, 17 fall through the classifier to
    `call`. `call` is the conservative answer and it is not the verb, so the
    policy says which tools it had to guess at instead of letting the operator
    assume the floor's write rules are engaged.
    """
    policy = compile_policy({
        "version": 1,
        "goal": {"id": "q", "summary": "manage infrastructure"},
        "tools": {"allow": ["terraform_destroy", "s3_put_object", "sql_query"]},
    })
    assert policy.unclassified_tools() == ["s3_put_object", "terraform_destroy"]
    assert any(f.code == "verb-not-declared" for f in policy.lint())

    declared = compile_policy({
        "version": 1,
        "goal": {"id": "q", "summary": "manage infrastructure"},
        "tools": {"allow": ["terraform_destroy", "s3_put_object", "sql_query"],
                  "effects": {"terraform_destroy": "write", "s3_put_object": "write"}},
    })
    assert declared.unclassified_tools() == []
    assert not any(f.code == "verb-not-declared" for f in declared.lint())


# --------------------------------------------------------------------------- #
# The path scope, which is where a foreign argument schema lands
# --------------------------------------------------------------------------- #
def _infra(**over):
    doc = {
        "version": 1,
        "goal": {"id": "q", "summary": "patch the staging web tier"},
        "profile": "supervised",
        "tools": {"allow": ["tf_apply"], "harmless": ["tf_apply"],
                  "effects": {"tf_apply": "write"}},
        "paths": {"allow": ["infra/staging/**"], "deny": ["infra/prod/**"]},
    }
    doc["paths"].update(over.pop("paths", {}))
    doc.update(over)
    return compile_policy(doc)


def _infra_proxy(policy):
    return McpProxy(gateway=policy.build(), allowed_tools=policy.allowed_tools,
                    tool_verbs=dict(policy.tool_verbs),
                    path_args=dict(policy.path_args),
                    pathless_tools=policy.pathless_tools,
                    log=lambda _m: None)


def test_a_path_the_gateway_cannot_find_is_refused_not_waved_through():
    """The worst failure this review found, and the reason for the whole check.

    The floor looks for `file_path`, `path`, `filename` and `file`. A tool that
    calls its argument `target_dir` yields no path, so the path scope was skipped
    and the write was ALLOWED. A policy denying `infra/prod/**` let a write to
    `infra/prod/web.tf` through, lint said clean, and nothing anywhere reported
    that a control had not been applied.
    """
    proxy = _infra_proxy(_infra())
    to_server, to_client = proxy.handle_client_message(json.dumps(
        _call("tf_apply", {"target_dir": "infra/prod/web.tf"})))
    assert to_server is None, "an unverifiable write reached the server"
    assert "path scope cannot be applied" in json.loads(to_client)["error"]["message"]


def test_declaring_the_argument_restores_the_scope():
    proxy = _infra_proxy(_infra(paths={"arg_names": {"tf_apply": "target_dir"}}))

    to_server, to_client = proxy.handle_client_message(json.dumps(
        _call("tf_apply", {"target_dir": "infra/prod/web.tf"}, id_=1)))
    assert to_server is None
    assert "outside scope" in json.loads(to_client)["error"]["message"]

    to_server, to_client = proxy.handle_client_message(json.dumps(
        _call("tf_apply", {"target_dir": "infra/staging/web.tf"}, id_=2)))
    assert to_server is not None and to_client is None


def test_a_default_argument_name_still_needs_no_declaration():
    proxy = _infra_proxy(_infra())
    to_server, _ = proxy.handle_client_message(json.dumps(
        _call("tf_apply", {"path": "infra/staging/web.tf"})))
    assert to_server is not None


def test_a_tool_declared_pathless_is_not_asked_for_a_path():
    policy = compile_policy({
        "version": 1,
        "goal": {"id": "q", "summary": "patch staging and announce it"},
        "profile": "supervised",
        "tools": {"allow": ["slack_post_message"], "harmless": ["slack_post_message"],
                  "effects": {"slack_post_message": "send"}},
        "paths": {"allow": ["infra/staging/**"], "pathless": ["slack_post_message"]},
        "egress": {"domains": ["slack.com"]},
    })
    proxy = _infra_proxy(policy)
    to_server, _ = proxy.handle_client_message(json.dumps(
        _call("slack_post_message", {"channel": "#sre", "text": "done"})))
    assert to_server is not None


def test_the_check_is_silent_when_no_path_scope_is_configured():
    """A deployment that never set a path scope is not missing one."""
    policy = compile_policy({
        "version": 1,
        "goal": {"id": "q", "summary": "patch the staging web tier"},
        "profile": "supervised",
        "tools": {"allow": ["tf_apply"], "harmless": ["tf_apply"],
                  "effects": {"tf_apply": "write"}},
    })
    proxy = _infra_proxy(policy)
    to_server, _ = proxy.handle_client_message(json.dumps(
        _call("tf_apply", {"target_dir": "anywhere/at/all"})))
    assert to_server is not None


def test_a_read_is_not_asked_for_a_path():
    policy = _infra(tools={"allow": ["tf_apply", "sql_query"],
                           "harmless": ["tf_apply", "sql_query"],
                           "effects": {"tf_apply": "write", "sql_query": "read"}})
    proxy = _infra_proxy(policy)
    to_server, _ = proxy.handle_client_message(json.dumps(
        _call("sql_query", {"statement": "select 1"})))
    assert to_server is not None


def test_lint_asks_the_question_without_blocking_the_deploy():
    """It cannot know whether a tool uses a default argument name, so it asks.

    An error here would refuse to start a perfectly good policy whose tools all
    happen to call the argument `path`. The runtime check sees the real arguments
    and is the control; this is the prompt.
    """
    undeclared = _infra()
    codes = {(f.code, f.level) for f in undeclared.lint()}
    assert ("path-arg-not-declared", "warning") in codes
    assert undeclared.tools_with_unverifiable_paths() == ["tf_apply"]

    declared = _infra(paths={"arg_names": {"tf_apply": "target_dir"}})
    assert declared.tools_with_unverifiable_paths() == []
    assert not any(f.code == "path-arg-not-declared" for f in declared.lint())
