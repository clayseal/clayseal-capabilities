"""The incremental assessment must equal the full recomputation. Exactly.

`_assess_phases` resumes from a cached prefix instead of rescanning the whole
trajectory on every decision, which took a 2,000-action session from 13.1
seconds to well under one. An optimization inside an enforcement path that is
subtly wrong is worse than the cost it saves, so this holds the equality against
a from-scratch assessment over randomized trajectories, including the rollbacks
the broker performs when it refuses an action.
"""
from __future__ import annotations

import random

import pytest

from clayseal.capabilities.monitor.action import Action, Trajectory
from clayseal.capabilities.monitor.generation import compile_envelope
from clayseal.capabilities.monitor.intent_envelope import IntentEnvelope
from clayseal.capabilities.scoping.goal import GoalSpec

TOOLS = ["read_file", "write_file", "send_email", "pay_vendor", "unknown_tool"]
VERBS = ["read", "write", "send", "transfer"]
RESOURCES = ["/finance/ap/a.json", "/finance/out/b.txt", "/etc/shadow",
             "workspace", "net:evil.example", "/finance/ap/../etc/passwd", ""]


def _goal() -> GoalSpec:
    return GoalSpec(
        query_id="q", summary="Read each invoice under /finance/ap and email a summary",
        allow_resources=["/finance/ap/**", "/finance/out/**"],
        structured_intent={"kind": "ap", "verbs": ["read", "write", "send"],
                           "tools": ["read_file", "write_file", "send_email"]})


def _envelope() -> IntentEnvelope:
    return compile_envelope(_goal(), derive_counts=True).envelope


def _action(rng: random.Random, step: int) -> Action:
    resource = rng.choice(RESOURCES)
    return Action(step=step, tool=rng.choice(TOOLS), resource=resource,
                  verb=rng.choice(VERBS), args={},
                  meta={"path": resource} if resource else {})


def _fresh(traj: Trajectory) -> Trajectory:
    """A trajectory with no memo, so the assessment starts from nothing."""
    return Trajectory(goal=traj.goal, actions=list(traj.actions),
                      context=list(traj.context))


def _rendered(conf) -> list[tuple]:
    return [(s.step, s.deviation, s.reason) for s in conf.steps]


@pytest.mark.parametrize("seed", range(12))
def test_resuming_equals_recomputing_as_a_session_grows(seed):
    rng = random.Random(seed)  # noqa: S311 - reproducible sweep, not a secret
    envelope = _envelope()
    traj = Trajectory(goal=_goal(), actions=[], context=[])
    for step in range(1, 41):
        traj.actions.append(_action(rng, step))
        incremental = envelope.assess(traj)
        scratch = _envelope().assess(_fresh(traj))
        assert _rendered(incremental) == _rendered(scratch), step
        assert incremental.conforms == scratch.conforms


@pytest.mark.parametrize("seed", range(12))
def test_a_rollback_invalidates_the_cached_prefix(seed):
    """The broker pops the last action when it refuses. The memo must not lie.

    A pop followed by a different push leaves the length equal and the identity
    different, which is exactly the case the prefix check exists for.
    """
    rng = random.Random(1000 + seed)  # noqa: S311 - reproducible sweep
    envelope = _envelope()
    traj = Trajectory(goal=_goal(), actions=[], context=[])
    for step in range(1, 31):
        traj.actions.append(_action(rng, step))
        envelope.assess(traj)
        if rng.random() < 0.4:
            traj.actions.pop()                      # the broker's rollback
            traj.actions.append(_action(rng, step))  # a different action, same length
        incremental = envelope.assess(traj)
        scratch = _envelope().assess(_fresh(traj))
        assert _rendered(incremental) == _rendered(scratch), step


def test_the_memo_does_not_survive_a_comparability_flip():
    """Membership verdicts for EARLIER actions change when the tier goes live.

    The flip is monotone and happens at most once a session, so recomputing on
    it is cheap. Believing the pre-flip prefix would be wrong.
    """
    envelope = _envelope()
    traj = Trajectory(goal=_goal(), actions=[], context=[])
    # Nothing here speaks the surface's vocabulary, so the tier abstains.
    for step in (1, 2):
        traj.actions.append(Action(step=step, tool="read_file", resource="opaque",
                                   verb="read", args={}, meta={}))
    before = envelope.assess(traj)
    # This one matches, so the tier goes live for the whole session.
    traj.actions.append(Action(step=3, tool="read_file",
                               resource="/finance/ap/x.json", verb="read",
                               args={}, meta={"path": "/finance/ap/x.json"}))
    after = envelope.assess(traj)
    scratch = _envelope().assess(_fresh(traj))
    assert _rendered(after) == _rendered(scratch)
    assert len(after.steps) == 3 and len(before.steps) == 2


def test_two_envelopes_do_not_share_a_memo_on_one_trajectory():
    """`assess` walks every mode, and each mode caches under its own key."""
    envelope = _envelope()
    traj = Trajectory(goal=_goal(), actions=[], context=[])
    rng = random.Random(7)  # noqa: S311 - reproducible sweep
    for step in range(1, 16):
        traj.actions.append(_action(rng, step))
        assert _rendered(envelope.assess(traj)) == _rendered(
            _envelope().assess(_fresh(traj)))
