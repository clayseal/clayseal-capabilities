"""Tamper-evident decision log + broker receipt emission (the L2->L3 seam)."""
from __future__ import annotations

import random

from agentauth.core.task_scope import TaskScope
from agentauth.capabilities.broker import Outcome, SessionBroker
from agentauth.capabilities.decision_log import DECISION_SCHEMA, DecisionLog
from agentauth.capabilities.monitor import Action, NGramScorer, TrajectoryDetector
from agentauth.capabilities.monitor.training.synth_corpus import generate, workflow_for
from agentauth.capabilities.scoping.goal import GoalSpec


def test_decision_log_chain_verifies_and_detects_tamper():
    log = DecisionLog(session_id="s1")
    for i in range(5):
        log.append(query_id="q", tool=f"t{i}", resource=f"mcp:tool:t{i}",
                   action_verb="read", arguments_hash="h", outcome="allow",
                   layer="-", reasons=(), anomaly_score=0.5)
    ok, err = log.verify()
    assert ok, err
    # Each link chains to the prior receipt_hash.
    recs = log.records()
    assert recs[0]["prev_hash"] == log.genesis
    assert recs[3]["prev_hash"] == recs[2]["receipt_hash"]
    assert all(r["schema"] == DECISION_SCHEMA for r in recs)

    # Tamper a past decision's outcome -> chain must break.
    log._records[2] = log._records[2].__class__(**{**log._records[2].__dict__, "outcome": "deny"})
    bad, why = log.verify()
    assert not bad and "hash" in (why or "")


def _broker_with_sink(sink):
    wf = workflow_for("invoice-reconcile")
    goal = wf.goal()
    scope = TaskScope(allowed_resources=list(goal.allow_resources),
                      allowed_actions=sorted({p.verb for p in wf.phases}),
                      task_summary=goal.summary)
    det = TrajectoryDetector(scorer=NGramScorer(), alpha=0.05)
    det.fit(generate(1500, seed=0))
    return SessionBroker(goal=goal, scope=scope, detector=det, receipt_sink=sink), wf


def test_broker_emits_chained_records_to_sink():
    emitted: list[dict] = []
    broker, wf = _broker_with_sink(emitted.append)
    traj = wf.sample(random.Random(3))
    for a in traj.actions:
        d = broker.authorize(a)
        assert d.record is not None and d.record["receipt_hash"].startswith("sha256:")
    # One record per authorization, all chained and verifiable.
    assert len(emitted) == len(traj.actions)
    ok, err = broker.decision_log.verify()
    assert ok, err
    # A denied out-of-scope action is still recorded (the audit trail is complete).
    d = broker.authorize(Action(99, "exfiltrate", "mcp:tool:exfiltrate", "send",
                                args={"to": "x@evil.test"}))
    assert d.outcome is Outcome.DENY
    assert emitted[-1]["decision"]["outcome"] == "deny"
    assert emitted[-1]["decision"]["layer"] == "floor"
    assert broker.decision_log.verify()[0]


def test_behavioral_record_carries_recomputable_anomaly_score():
    broker, wf = _broker_with_sink(lambda r: None)
    # Drive an in-scope burst to a behavioral denial; its record carries the score.
    read = next(p for p in wf.phases if p.verb == "read")
    last = None
    for i in range(25):
        last = broker.authorize(Action(i, read.tool, f"mcp:tool:{read.tool}", "read"))
        if last.outcome is Outcome.DENY:
            break
    assert last is not None and last.outcome is Outcome.DENY and last.layer == "behavioral"
    assert last.record["decision"]["anomaly_score"] is not None
