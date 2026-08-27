"""Adding a human to the loop must not change what the loop does without one.

`gate_with_supervision` was added so a STEP_UP could be a question rather than a
halt, which is what turns "supervised utility" from arithmetic into a
measurement. That is only worth anything if the new path is *identical* to the
old one when nobody answers, otherwise every published autonomous number was
produced by different code from the one now shipping, and the comparison between
supervised and autonomous is between two things that differ in more than
supervision.

The plan states it as W1's verification: **`NeverApprove` must reproduce today's
autonomous numbers exactly.** This is that check. Two forms, because they fail
differently:

    approver=None       the loop is never entered at all
    NeverApprove        the loop is entered, `review` returns None, the step-up
                        stands

The second is the one that matters. It exercises the whole path, building the
action, authorizing, entering the while loop, asking, being declined, breaking
and must still land on the same verdict.
"""
from __future__ import annotations

import pytest

from agentauth.capabilities.broker import Outcome, SessionBroker
from agentauth.capabilities.monitor.action import Action
from agentauth.capabilities.scoping.goal import GoalSpec
from benchmarks.live.approver import NeverApprove

# `broker_defense` imports `agentdojo`, which is an optional benchmark
# dependency and is not installed in the fast gate. Importing it at module
# scope turned a missing optional dependency into a COLLECTION error, which
# fails the whole job rather than skipping one file: five consecutive nightly
# `invariants` runs went red on this and nothing else.
pytest.importorskip("agentdojo", reason="optional benchmark dependency")

from benchmarks.live.broker_defense import (  # noqa: E402 - after the skip
    LiveBrokerHarness,
    classify_verb,
)

#: A spread of tools chosen to land on all three outcomes: in-scope reads,
#: an out-of-scope write, and an egress with a destination nothing granted.
CALLS = [
    ("read_file", {"path": "/app/data/report.csv"}),
    ("search", {"query": "quarterly numbers"}),
    ("write_file", {"path": "/etc/shadow", "content": "x"}),
    ("send_email", {"to": "auditor@novel.test", "body": "report"}),
    ("send_money", {"recipient": "acct-999", "amount": "5000"}),
    ("read_file", {"path": "/app/data/report.csv"}),
]


def _harness() -> LiveBrokerHarness:
    harness = LiveBrokerHarness(mode="floor")
    harness.query = "produce the quarterly report"
    harness._identity = set()
    harness._named = set()
    harness.broker = SessionBroker(goal=GoalSpec(
        query_id="live", summary="produce the quarterly report",
        allow_resources=["mcp:tool:read_file", "mcp:tool:search"]))
    return harness


def _verdicts_via_gate() -> list[tuple[str, bool]]:
    harness = _harness()
    return [(tool, harness.gate(tool, args)[0]) for tool, args in CALLS]


def _verdicts_via_supervision(approver) -> list[tuple[str, bool]]:
    harness = _harness()
    return [(tool, harness.gate_with_supervision(tool, args, approver=approver)[0])
            for tool, args in CALLS]


def test_supervision_with_no_approver_matches_the_autonomous_gate():
    assert _verdicts_via_supervision(None) == _verdicts_via_gate()


def test_supervision_with_never_approve_matches_the_autonomous_gate():
    """The regression the plan asks for, and the stronger of the two.

    This one walks the entire supervision path, action built, authorized, loop
    entered, approver asked, declined, loop broken, and still has to agree with
    the gate that never had a loop.
    """
    assert _verdicts_via_supervision(NeverApprove()) == _verdicts_via_gate()


def test_a_declining_approver_records_no_resolutions():
    harness = _harness()
    for tool, args in CALLS:
        harness.gate_with_supervision(tool, args, approver=NeverApprove())
    assert harness.resolutions == []
    assert harness.round_trips == 0
    assert harness.supervised_allows == 0


def test_the_allow_and_block_counters_agree_between_the_two_paths():
    """Not just the verdicts: the counters feed the published friction column."""
    autonomous = _harness()
    for tool, args in CALLS:
        autonomous.gate(tool, args)

    supervised = _harness()
    for tool, args in CALLS:
        supervised.gate_with_supervision(tool, args, approver=NeverApprove())

    assert (supervised.allows, supervised.blocks) == (autonomous.allows,
                                                      autonomous.blocks)


def test_the_calls_actually_exercise_more_than_one_outcome():
    """Guard on the guard.

    If every call in `CALLS` were allowed, the parity tests above would pass on a
    supervision path that was completely broken for step-ups. This asserts the
    fixture still produces a refusal, so the comparison has something to compare.
    """
    broker = _harness().broker
    outcomes = set()
    for step, (tool, args) in enumerate(CALLS):
        outcomes.add(broker.authorize(Action(
            step=step, tool=tool, resource=f"mcp:tool:{tool}",
            verb=classify_verb(tool), args=dict(args))).outcome)
    assert Outcome.ALLOW in outcomes
    assert outcomes - {Outcome.ALLOW}, "no call is refused; parity proves nothing"
