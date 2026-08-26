"""The entailment judge cannot hold the session lock indefinitely.

The judge is a remote model called from inside `SessionBroker.authorize`, under
the session lock. Before this bound existed there was no `timeout=` anywhere in
its path: the OpenAI SDK's default is 600 seconds per request with its own
internal retries, and `llm_entailment_judge` wrapped that in four more attempts.
A slow endpoint therefore stalled a session for as long as it liked, on a code
path whose only possible output is a soft STEP_UP, and making an endpoint slow
is something an attacker can do on purpose.

These tests assert the ceiling holds for the two cases that differ: a judge that
respects nothing (a hung callable), and a judge that raises.
"""
from __future__ import annotations

import time

from agentauth.capabilities.broker import SessionBroker
from agentauth.capabilities.monitor.action import Action
from agentauth.capabilities.monitor.llm_clients import bounded
from agentauth.capabilities.scoping.goal import GoalSpec


def test_a_hung_judge_returns_within_the_budget():
    def never_answers(goal, samples):
        time.sleep(30)
        return ["should never be seen"]

    judge = bounded(never_answers, budget_seconds=0.25)
    started = time.monotonic()
    assert judge("goal", [{"tool": "t", "dest": "d", "snippet": "x"}]) == []
    assert time.monotonic() - started < 5.0


def test_a_raising_judge_fails_open_rather_than_propagating():
    def explodes(goal, samples):
        raise RuntimeError("rate limited, permanently")

    assert bounded(explodes, budget_seconds=1.0)("goal", []) == []


def test_the_broker_bounds_a_judge_it_was_handed():
    """The ceiling belongs to the gateway, not to the judge's own good manners.

    A caller can pass any callable as `entailment_judge`. `__post_init__` wraps
    it, so the bound is a property of the broker rather than a convention every
    integration has to remember.
    """
    def never_answers(goal, samples):
        time.sleep(30)
        return ["nope"]

    broker = SessionBroker(
        goal=GoalSpec(query_id="q", summary="summarise the tickets"),
        entailment_judge=never_answers,
        judge_budget_seconds=0.25,
    )
    assert broker.entailment_judge is not never_answers

    started = time.monotonic()
    assert broker.entailment_judge("goal", []) == []
    assert time.monotonic() - started < 5.0


def test_a_slow_judge_does_not_stall_authorize():
    """The property that matters: authorize() returns, and the lock comes back."""
    def never_answers(goal, samples):
        time.sleep(30)
        return ["off-goal"]

    broker = SessionBroker(
        goal=GoalSpec(query_id="q", summary="summarise the tickets"),
        entailment_judge=never_answers,
        judge_budget_seconds=0.25,
    )
    def _write(step: int) -> Action:
        return Action(
            step=step,
            tool="write_summary",
            verb="write",
            resource="repo_write://out/summary.md",
            args={"path": "out/summary.md", "content": "x" * 200},
        )

    started = time.monotonic()
    broker.authorize(_write(0))
    assert time.monotonic() - started < 10.0

    # And the lock is free afterwards, so the session is still usable.
    broker.authorize(_write(1))


def test_no_judge_configured_stays_none():
    broker = SessionBroker(goal=GoalSpec(query_id="q", summary="anything"))
    assert broker.entailment_judge is None
