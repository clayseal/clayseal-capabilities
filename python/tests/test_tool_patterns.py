"""`tools.patterns`: the grant surface the benchmark could reach and the document could not.

`SessionBroker.tool_patterns` has been enforced since the pattern work landed,
and until now only `benchmarks/core/patterns.py` could set it. So
`generalisation.md`'s result, held-out false blocks falling from 47.91% to 0.05%
on tau2 once a grant is written as patterns rather than as the instance list a
logger produces, was measured against a mechanism no user could deploy.

These tests cover the wiring and, more importantly, the guards: a pattern grant
is the one part of a policy document whose extent is not visible from reading it.
"""
from __future__ import annotations

import pytest

from clayseal.capabilities.monitor.action import Action
from clayseal.capabilities.policy import PolicyError, compile_policy

BASE = {
    "version": 1,
    "goal": {"id": "t", "summary": "look up reservations"},
    "expires_at": "2030-01-01T00:00:00Z",
}


def _policy(pathless=(), **tools):
    """Compile a policy. `pathless` must name only tools the grant covers.

    The cross-checks are the point of the feature, so the fixture does not get
    to opt out of them: an earlier version declared a fixed pathless list and
    four tests failed because the validator correctly refused a tool their
    patterns did not grant.
    """
    raw = dict(BASE)
    raw["tools"] = tools
    if pathless:
        raw["paths"] = {"pathless": list(pathless)}
    return compile_policy(raw)


def test_a_pattern_grant_reaches_the_broker_and_is_enforced():
    policy = _policy(pathless=["get_reservation", "search_flights"],
                     patterns=["get_*", "search_*"],
                     effects={"get_reservation": "read"})
    gateway = policy.build()
    assert gateway.broker.tool_patterns == ["get_*", "search_*"]

    def outcome(tool):
        return gateway.authorize(
            Action(0, tool, f"mcp:tool:{tool}", "read", args={})).outcome

    assert outcome("get_reservation") == "allow"
    assert outcome("search_flights") == "allow"
    assert outcome("delete_everything") == "deny"


def test_literals_and_patterns_union():
    """`allow` keeps meaning exactly what it meant; patterns add to it."""
    policy = _policy(pathless=["cancel_booking", "get_reservation"],
                     allow=["cancel_booking"], patterns=["get_*"],
                     effects={"cancel_booking": "write"})
    gateway = policy.build()

    def allowed(tool):
        return gateway.authorize(
            Action(0, tool, f"mcp:tool:{tool}", "read", args={})).allowed

    assert allowed("cancel_booking")          # literal
    assert allowed("get_reservation")         # pattern
    assert not allowed("refund_booking")      # neither


@pytest.mark.parametrize("bad", [["*"], ["**"], ["?*"]])
def test_a_universal_pattern_is_refused_at_compile_time(bad):
    """The `path-scope-universal` rule, one dimension over.

    A grant of everything is not a grant, and refusing it at compile time rather
    than warning is deliberate: this field's whole purpose is to be read in a
    pull request, and `*` is unreadable.
    """
    with pytest.raises(PolicyError, match="universal pattern"):
        _policy(patterns=bad)


def test_a_literal_in_the_pattern_field_is_refused():
    """Otherwise the two fields blur and a reader cannot tell a name from a family."""
    with pytest.raises(PolicyError, match="no wildcard"):
        _policy(patterns=["get_reservation"])


def test_effects_may_name_a_tool_only_a_pattern_covers():
    """`effects` validation has to know about patterns or the feature is unusable.

    Declaring what a tool does is how the floor knows whether it writes or sends,
    and a catalog granted by pattern still needs that. Before this, naming one
    raised `tools.effects names tools that are not in tools.allow`.
    """
    policy = _policy(pathless=["get_reservation"], patterns=["get_*"],
                     effects={"get_reservation": "read"})
    assert policy.tool_verbs["get_reservation"] == "read"

    with pytest.raises(PolicyError, match="tools.allow"):
        _policy(patterns=["get_*"], effects={"wire_funds": "transfer"})


def test_lint_says_the_extent_is_not_in_the_file():
    policy = _policy(pathless=["get_reservation"], patterns=["get_*"],
                     effects={"get_reservation": "read"})
    codes = {f.code for f in policy.lint()}
    assert "tool-pattern-grant" in codes
    assert "no-tool-allowlist" not in codes      # patterns ARE a scope

    leading = _policy(patterns=["*_data"])
    codes = {f.code for f in leading.lint()}
    assert "tool-pattern-leading-wildcard" in codes


def test_the_proxy_gates_agree_with_each_other():
    """A catalog filter that disagrees with the call check is worse than either.

    Either the agent is told a tool does not exist and then allowed to call it,
    or it is offered one and refused. Both gates go through `_tool_granted`.
    """
    from clayseal.capabilities.mcp_proxy import McpProxy

    policy = _policy(pathless=["get_reservation"], patterns=["get_*"],
                     effects={"get_reservation": "read"})
    proxy = McpProxy.from_policy(policy)
    assert proxy.tool_patterns == ["get_*"]

    for name in ("get_reservation", "get_flight", "wire_funds"):
        granted = proxy._tool_granted(name)
        allowed, _ = proxy.check({"name": name, "arguments": {}})
        assert granted == allowed, name

    listing = proxy.handle_server_message(__import__("json").dumps({
        "jsonrpc": "2.0", "id": 1,
        "result": {"tools": [{"name": "get_reservation"}, {"name": "wire_funds"}]},
    }))
    advertised = {t["name"] for t in __import__("json").loads(listing)["result"]["tools"]}
    assert advertised == {"get_reservation"}
