"""Phase C3: behavior-tree envelope (explicit multi-modal branching) and the
ATC-style re-clearance loop."""
from __future__ import annotations

from clayseal.capabilities.broker import Outcome, SessionBroker
from clayseal.capabilities.monitor import (
    Action,
    IntentEnvelope,
    Trajectory,
    envelope_from_tree,
    leaf,
    linearize,
    loop,
    selector,
    sequence,
    sign_intent_envelope,
)
from clayseal.capabilities.scoping.goal import GoalSpec
from clayseal.core.signing import generate_keypair
from clayseal.core.task_scope import TaskScope

# Two genuinely different plans for "resolve the ticket":
#   mode A: investigate -> patch -> verify
#   mode B: reproduce -> rollback
_TREE = selector(
    sequence(leaf(tools=["investigate"], min=1),
             leaf(tools=["patch"], min=1),
             leaf(tools=["verify"], min=1)),
    sequence(leaf(tools=["reproduce"], min=1),
             leaf(tools=["rollback"], min=1)),
)


def _a(step, tool, verb="write"): return Action(step, tool, f"mcp:tool:{tool}", verb)


def test_linearize_yields_two_modes():
    modes = linearize(_TREE)
    assert len(modes) == 2
    assert {tuple(sorted(t for p in m for t in p.tools)) for m in modes} == {
        ("investigate", "patch", "verify"), ("reproduce", "rollback")}


def _goal(): return GoalSpec(query_id="ticket", summary="resolve the ticket",
                            structured_intent={"verbs": ["write"]})


def _env(): return envelope_from_tree(_TREE, verbs=["write"])


def test_either_mode_conforms():
    env = _env()
    a = Trajectory(goal=_goal(), actions=[_a(0, "investigate"), _a(1, "patch"), _a(2, "verify")])
    b = Trajectory(goal=_goal(), actions=[_a(0, "reproduce"), _a(1, "rollback")])
    assert env.assess(a).conforms
    assert env.assess(b).conforms


def test_crossing_modes_deviates():
    env = _env()
    # investigate (mode A) then rollback (mode B): no single mode explains it.
    mixed = Trajectory(goal=_goal(), actions=[_a(0, "investigate"), _a(1, "rollback")])
    assert env.last_deviation(mixed) is not None


def test_out_of_order_within_a_mode_deviates():
    env = _env()
    # patch before investigate (mode A requires investigate first); mode B does
    # not admit patch at all -> no live mode.
    bad = Trajectory(goal=_goal(), actions=[_a(0, "patch")])
    assert env.last_deviation(bad) is not None


def test_multimode_envelope_roundtrips():
    env = _env()
    rebuilt = IntentEnvelope.from_dict(env.to_dict())
    assert len(rebuilt.modes) == 2
    a = Trajectory(goal=_goal(), actions=[_a(0, "reproduce"), _a(1, "rollback")])
    assert rebuilt.assess(a).conforms


# -- re-clearance -----------------------------------------------------------
def test_reclearance_swaps_a_signed_envelope_midsession():
    key = generate_keypair()
    goal = _goal()
    # Start under a narrow plan: only mode B (reproduce -> rollback).
    narrow = envelope_from_tree(
        sequence(leaf(tools=["reproduce"], min=1), leaf(tools=["rollback"], min=1)), verbs=["write"])
    scope = TaskScope(allowed_resources=[f"mcp:tool:{t}" for t in
                     ("reproduce", "rollback", "investigate", "patch", "verify")],
                     allowed_actions=["write"])
    broker = SessionBroker(goal=goal, scope=scope, intent_envelope=narrow, detector=None)

    # 'investigate' is off-plan under the narrow envelope (consequential write) -> deny.
    assert broker.authorize(_a(0, "investigate")).outcome is Outcome.DENY

    # The control plane re-clears with the broader two-mode plan, signed.
    signed = sign_intent_envelope(_env(), key=key)
    assert broker.reclear(signed=signed, trusted_keys={key.public_key_hex})
    # Now investigate -> patch -> verify is on-plan.
    assert broker.authorize(_a(1, "investigate")).outcome is Outcome.ALLOW
    assert broker.authorize(_a(2, "patch")).outcome is Outcome.ALLOW
    # The re-clearance is on the audit chain and it still verifies.
    assert broker.decision_log.verify()[0]
    assert any(r["action"]["verb"] == "reclear" for r in broker.decision_log.records())


def test_reclearance_rejects_untrusted_signer():
    broker = SessionBroker(goal=_goal(), scope=None, intent_envelope=_env(), detector=None)
    attacker = generate_keypair(); trusted = generate_keypair()
    signed = sign_intent_envelope(_env(), key=attacker)
    assert not broker.reclear(signed=signed, trusted_keys={trusted.public_key_hex})


def test_nfa_handles_nested_selectors_and_loops():
    from clayseal.capabilities.monitor import envelope_from_tree
    # A loop of reads, then either (design->build) or (buy), then deploy.
    tree = sequence(
        loop(leaf(tools=["read"]), min=1),
        selector(
            sequence(leaf(tools=["design"], min=1), leaf(tools=["build"], min=1)),
            leaf(tools=["buy"], min=1)),
        leaf(tools=["deploy"], min=1))
    env = envelope_from_tree(tree, verbs=["write"])
    g = _goal()
    # Path 1: read read design build deploy
    t1 = Trajectory(goal=g, actions=[_a(0, "read"), _a(1, "read"), _a(2, "design"),
                                     _a(3, "build"), _a(4, "deploy")])
    assert env.assess(t1).conforms
    # Path 2: read buy deploy
    t2 = Trajectory(goal=g, actions=[_a(0, "read"), _a(1, "buy"), _a(2, "deploy")])
    assert env.assess(t2).conforms
    # Deploy before the middle phase is out of order.
    bad = Trajectory(goal=g, actions=[_a(0, "read"), _a(1, "deploy")])
    assert env.last_deviation(bad) is not None
    # Serialized tree still enforces the same structure.
    rebuilt = IntentEnvelope.from_dict(env.to_dict())
    assert rebuilt.plan_tree is not None and rebuilt.assess(t2).conforms
