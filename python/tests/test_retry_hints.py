"""Re-audited retry with trusted destination hints (ARGUS-style utility path)."""
from __future__ import annotations

from agentauth.capabilities.broker import Outcome, SessionBroker
from agentauth.capabilities.hardening.egress_policy import EgressPolicy
from agentauth.capabilities.monitor.action import Action
from agentauth.capabilities.parameter_provenance import ParameterProvenance
from agentauth.capabilities.retry_hints import reaudited_retry, rewrite_destination_args
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.core.task_scope import TaskScope


def test_rewrite_replaces_destination_not_body():
    out = rewrite_destination_args(
        {"to": "attacker@evil.test", "body": "launch notes"},
        "bob@corp.example",
    )
    assert out == {"to": "bob@corp.example", "body": "launch notes"}


def test_rewrite_noop_when_already_candidate():
    assert rewrite_destination_args(
        {"to": "bob@corp.example"}, "bob@corp.example") is None


def test_rewrite_none_without_destination_key():
    assert rewrite_destination_args({"body": "hi"}, "bob@corp.example") is None


def test_reaudited_retry_goes_through_gate():
    calls: list[dict] = []

    def gate(tool, args):
        calls.append(dict(args))
        if args.get("to") == "bob@corp.example":
            return True, "ok"
        return False, "bad dest"

    ok, reason, used, cand = reaudited_retry(
        gate, "send_email",
        {"to": "attacker@evil.test", "body": "x"},
        ["bob@corp.example"],
    )
    assert ok and cand == "bob@corp.example"
    assert used["to"] == "bob@corp.example"
    assert used["body"] == "x"
    assert len(calls) == 1
    assert calls[0]["to"] == "bob@corp.example"


def test_reaudited_retry_failure_does_not_bypass():
    def gate(tool, args):
        return False, "still blocked"

    ok, _, used, cand = reaudited_retry(
        gate, "send_email",
        {"to": "attacker@evil.test"},
        ["bob@corp.example"],
    )
    assert not ok and cand is None
    assert used["to"] == "attacker@evil.test"


def test_broker_lists_allowlist_on_deny_even_without_observation():
    """Frontier: hints from allow-list + provenance, not provenance alone."""
    b = SessionBroker(
        goal=GoalSpec(query_id="t", summary="pay bob@corp.example"),
        scope=TaskScope(
            allowed_resources=["mcp:tool:send_email"],
            allowed_actions=["send"]),
        egress=EgressPolicy(
            bind_recipients=True, allow_all=False,
            allowed_recipients={"bob@corp.example"},
            allowed_domains={"corp.example"}),
        provenance=ParameterProvenance(),
    )
    d = b.authorize(Action(
        0, "send_email", "mcp:tool:send_email", "send",
        args={"to": "attacker@evil.test", "body": "x"}))
    assert d.outcome is Outcome.DENY
    assert "bob@corp.example" in d.trusted_candidates


def test_stack_decision_carries_candidates():
    from agentauth.capabilities.deployable_stack import DeployableStack

    stack = DeployableStack.from_goal(
        GoalSpec(query_id="t", summary="email bob@corp.example"),
        scope=TaskScope(
            allowed_resources=["mcp:tool:send_email"],
            allowed_actions=["send"]),
        egress=EgressPolicy(
            bind_recipients=True, allow_all=False,
            allowed_recipients={"bob@corp.example"},
            allowed_domains={"corp.example"}),
        entailment_judge=None,
        enable_replan=False,
    )
    d = stack.authorize(Action(
        0, "send_email", "mcp:tool:send_email", "send",
        args={"to": "attacker@evil.test"}))
    assert not d.allowed
    assert "bob@corp.example" in d.trusted_candidates
    assert "bob@corp.example" in stack.last_trusted_candidates()
