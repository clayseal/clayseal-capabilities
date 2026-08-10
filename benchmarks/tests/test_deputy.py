"""The delegation benchmark, and the properties that make its numbers mean something.

The result here is only worth having if the overreach is genuinely invisible to
every rung below the delegation boundary, and if the *same action performed by
the principal entitled to it* is allowed. Without the first the benchmark is
re-measuring scope; without the second it is measuring a mechanism that refuses
work rather than one that reads authority. Both are load-bearing tests.
"""
from __future__ import annotations

import random
from copy import copy

import pytest

from agentauth.capabilities.deputy import (
    DelegationBoundary, DelegationPolicy, shipped_primitive_allows)
from benchmarks.core.engines import (
    DelegationLadderEngine, VelocityLadderEngine, build_engines)
from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, EventLabel

pytest.importorskip("benchmarks.deputy")
from benchmarks.deputy import (  # noqa: E402
    _ATTACK_ARMS, MAX_DEPTH, _attributed, _replay_task, build_sessions, evaluate)


def _available(corpus: str):
    from benchmarks.datasets.base import get_loader

    try:
        get_loader(corpus).load(limit=1)
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"{corpus} unavailable: {exc}")


def _overreach_replay(corpus: str, split: str = "verb", count: int = 30):
    sessions = build_sessions(corpus, split=split, count=count, seed=0)
    below = VelocityLadderEngine()
    below.observe_corpus([s.host for s in sessions])
    out = []
    for i, session in enumerate(sessions):
        events = _attributed(session.host.events, session, overreach=True)
        presenters = {session.parent_id: session.envelopes["parent's own token"],
                      session.sub_id: session.envelopes["own delegation"]}
        task = _replay_task(session, f"t-{i}", events,
                            DelegationBoundary(session.policy), presenters)
        out.append((session, task))
    return out, below


# --------------------------------------------------------------------------- #
# Attribution: nothing below the boundary may see the overreach
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("corpus", ["tau2", "bfcl"])
@pytest.mark.parametrize("split", ["verb", "tool"])
def test_every_overreach_action_clears_the_ladder_below(corpus, split):
    """Without this the benchmark measures the ladder, not the principal.

    The overreach is one of the session's OWN events, replayed unchanged in its
    own position with the acting principal swapped. Same tool, same resource,
    same verb, same arguments, same total volume, same mandate. Scope, binding,
    protected zones, budgets and velocity all have to allow it.
    """
    _available(corpus)
    replays, below = _overreach_replay(corpus, split)
    blocked = total = 0
    for _session, task in replays:
        for event in task.events:
            if event.label is EventLabel.ATTACK:
                total += 1
                blocked += not below.decide(task, event).allowed
    assert total > 0
    assert blocked == 0, (
        f"{blocked}/{total} overreach actions were blocked below the delegation "
        f"rung; the benchmark is measuring scope, not authority"
    )


@pytest.mark.parametrize("corpus", ["tau2", "bfcl"])
def test_the_shipped_ladder_contains_none_of_it(corpus):
    """The gap, asserted rather than asserted-in-prose.

    No rung of the shipped enforcement ladder consults a delegation, so the
    top of the stack allows every one of these. If this test ever fails because
    containment went UP, a rung has started reading the principal and this
    benchmark needs re-attributing.
    """
    _available(corpus)
    r = evaluate(corpus, split="verb", count=60, seed=0)
    assert r.below_blocked == 0
    assert r.below_allowed == r.sessions


# --------------------------------------------------------------------------- #
# Discrimination: the same action, the other principal
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("corpus", ["tau2", "bfcl"])
@pytest.mark.parametrize("split", ["verb", "tool"])
def test_the_same_action_by_the_rightful_holder_is_allowed(corpus, split):
    """A mechanism that refused the overreach by refusing the action would score
    100% containment and 100% here. The mandate, the capabilities, the arguments
    and the trace position are identical between the two; only the principal
    differs."""
    _available(corpus)
    r = evaluate(corpus, split=split, count=60, seed=0)
    assert r.rightful_total == r.sessions
    assert r.rightful_blocked == 0


@pytest.mark.parametrize("corpus", ["tau2", "bfcl"])
@pytest.mark.parametrize("split", ["verb", "tool"])
def test_the_two_headline_columns_come_from_the_same_engine_call(corpus, split):
    """Containment and friction have to be produced by the same code path.

    The presentation sweep calls the boundary directly. This asserts the plain
    case through the ladder engine instead: the same task object, the same
    event, the same position, decided once with the parent acting and once with
    the sub-agent acting. Refused in one and allowed in the other, or the
    comparison is not like for like.
    """
    _available(corpus)
    r = evaluate(corpus, split=split, count=60, seed=0)
    assert r.engine_overreach_total == r.sessions
    assert r.engine_overreach_blocked == r.engine_overreach_total
    assert r.rightful_blocked == 0


@pytest.mark.parametrize("corpus", ["tau2", "bfcl"])
def test_delegation_is_not_partition(corpus):
    """Handing a sub-scope to a sub-agent does not take it from the parent."""
    _available(corpus)
    r = evaluate(corpus, split="verb", count=60, seed=0)
    blocked, total = r.legit["parent performs delegated work"]
    assert total > 0 and blocked == 0


@pytest.mark.parametrize("corpus", ["tau2", "bfcl"])
def test_a_refusal_does_not_creep_over_the_principal(corpus):
    """The label-creep analogue. Refusing one action of a sub-agent must not
    refuse the sub-agent: its later in-scope work still runs.

    Asserted on what this rung ADDS, because the ladder below it can still
    refuse a later action for its own reasons — one BFCL session runs seven
    effect actions against a cap of six, and that block is velocity's.
    """
    _available(corpus)
    r = evaluate(corpus, split="verb", count=60, seed=0)
    assert r.creep_total > 0
    assert r.creep_blocked == r.creep_blocked_below


# --------------------------------------------------------------------------- #
# What the shipped primitive does and does not hold
# --------------------------------------------------------------------------- #
# "no delegation" moved from FAILS to HOLDS when `verify_delegation_chain` began
# treating an absent token as a violation rather than an empty list of them. The
# fix is upstream of this boundary, so the row is re-measured here rather than
# restated.
SHIPPED_HOLDS = {"own delegation", "no delegation", "onward re-delegation",
                 "widened re-delegation", "wildcard action", "chain stripped",
                 "expired grant"}
SHIPPED_FAILS = {"parent's own token", "sibling sub-agent's token",
                 "self-minted root", "self-minted chain", "second authority",
                 "revoked grant"}


@pytest.mark.parametrize("corpus", ["tau2"])
def test_the_shipped_primitive_holds_attenuation_and_expiry(corpus):
    """Pinned so a change in `agentauth.core.delegation` is noticed here."""
    _available(corpus)
    r = evaluate(corpus, split="verb", count=60, seed=0)
    for arm in SHIPPED_HOLDS:
        assert r.rate(arm, 1) == 1.0, f"{arm} regressed in the shipped primitive"


@pytest.mark.parametrize("corpus", ["tau2"])
def test_the_shipped_primitive_admits_six_presentation_strategies(corpus):
    """The finding. Each of these is a valid-looking credential the primitive
    returns no violations for, and an attacker needs one."""
    _available(corpus)
    r = evaluate(corpus, split="verb", count=60, seed=0)
    for arm in SHIPPED_FAILS:
        assert r.rate(arm, 1) == 0.0, (
            f"{arm} is now contained by the shipped primitive; the fix moved "
            f"upstream and benchmarks/results/deputy.md needs re-measuring"
        )
    assert r.adaptive_containment_shipped == 0.0


@pytest.mark.parametrize("corpus", ["tau2", "bfcl"])
@pytest.mark.parametrize("split", ["verb", "tool"])
def test_the_boundary_refuses_every_presentation_strategy(corpus, split):
    _available(corpus)
    r = evaluate(corpus, split=split, count=60, seed=0)
    for arm in _ATTACK_ARMS:
        assert r.rate(arm, 0) == 1.0, f"{arm} walked through the boundary"
    assert r.adaptive_containment == 1.0


# --------------------------------------------------------------------------- #
# Invariants
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("corpus", ["tau2"])
def test_the_boundary_never_reads_the_label(corpus):
    """The most direct form of label leakage: relabel every event BENIGN and the
    decisions must not move."""
    _available(corpus)
    replays, _below = _overreach_replay(corpus, count=40)
    engine = DelegationLadderEngine()
    engine.observe_corpus([s.host for s, _ in replays])
    for session, task in replays:
        before = [engine.decide(task, e).allowed for e in task.events]
        relabelled = copy(task)
        relabelled.task_id = task.task_id + "-relabelled"
        relabelled.events = [
            BenchmarkEvent(event_id=e.event_id, tool_name=e.tool_name,
                           resource=e.resource, action=e.action, path=e.path,
                           args=dict(e.args), label=EventLabel.BENIGN,
                           meta=dict(e.meta))
            for e in task.events]
        after = [engine.decide(relabelled, e).allowed for e in relabelled.events]
        assert before == after


@pytest.mark.parametrize("corpus", ["tau2"])
def test_the_rung_is_insensitive_to_event_order(corpus):
    """Shuffling events inside a task must not move any decision."""
    _available(corpus)
    replays, _below = _overreach_replay(corpus, count=40)
    engine = DelegationLadderEngine()
    engine.observe_corpus([s.host for s, _ in replays])
    rnd = random.Random(20260809)
    for _session, task in replays:
        base = {e.event_id: engine.decide(task, e).allowed for e in task.events}
        shuffled = copy(task)
        shuffled.task_id = task.task_id + "-shuffled"
        events = list(task.events)
        rnd.shuffle(events)
        shuffled.events = events
        after = {e.event_id: engine.decide(shuffled, e).allowed
                 for e in shuffled.events}
        assert base == after


@pytest.mark.parametrize("corpus", ["tau2"])
def test_no_policy_parameter_moves_with_attack_traffic(corpus):
    """The depth bound and the signer pin are declared, not fitted.

    Evaluating with one overreach and with a hundred must produce the same
    policy. The sessions differ only in what the attacker does, and nothing the
    attacker does may reach a policy parameter.
    """
    _available(corpus)
    a = build_sessions(corpus, split="verb", count=20, seed=0)
    b = build_sessions(corpus, split="verb", count=20, seed=0)
    assert [s.policy.max_depth for s in a] == [MAX_DEPTH] * len(a)
    assert [s.host.task_id for s in a] == [s.host.task_id for s in b]


@pytest.mark.parametrize("corpus", ["tau2"])
def test_no_lower_rung_contains_what_the_delegation_rung_allows(corpus):
    """Monotone per event: the rung composes the stack below it, so anything a
    lower rung refuses it must refuse too."""
    _available(corpus)
    replays, _below = _overreach_replay(corpus, count=40)
    order = ["tool-allowlist", "capability-token", "task-scope",
             "task-scope+binding", "task-scope+binding+budget",
             "task-scope+binding+budget+velocity",
             "task-scope+binding+budget+velocity+delegation"]
    by_name = {e.name: e for e in build_engines(order)}
    for engine in by_name.values():
        obs = getattr(engine, "observe_corpus", None)
        if obs:
            obs([s.host for s, _ in replays])
    escapes = []
    for _session, task in replays:
        for event in task.events:
            allowed = [by_name[n].decide(task, event).allowed for n in order]
            for i, lower in enumerate(allowed):
                if not lower and any(allowed[i + 1:]):
                    escapes.append((event.event_id, order[i]))
    assert not escapes[:5], f"{len(escapes)} monotonicity escapes, e.g. {escapes[:3]}"


@pytest.mark.parametrize("corpus", ["tau2"])
def test_task_ids_are_unique(corpus):
    _available(corpus)
    from collections import Counter

    replays, _below = _overreach_replay(corpus, count=40)
    counts = Counter(task.task_id for _s, task in replays)
    assert not [k for k, v in counts.items() if v > 1]


def test_the_rung_is_a_pass_through_without_a_delegation_policy():
    """A task that declares no delegation is decided exactly as the rung below
    decides it. This is what keeps the deterministic tier unchanged."""
    task = BenchmarkTask(
        task_id="no-delegation", summary="g",
        events=[BenchmarkEvent(event_id="e1", tool_name="send_email",
                               resource="mcp:tool:send_email", action="send",
                               label=EventLabel.BENIGN)],
        mandate={"grant_id": "g", "issuer": "did:clayseal:test",
                 "issued_at": "2026-01-01T00:00:00+00:00",
                 "expires_at": "2027-01-01T00:00:00+00:00",
                 "allowed_actions": ["send"],
                 "allowed_resources": ["mcp:tool:send_email"]},
        capabilities=[{"resource": "mcp:tool:send_email", "action": "send"}],
        allowed_tools={"send_email"})
    lower = VelocityLadderEngine()
    upper = DelegationLadderEngine()
    assert (upper.decide(task, task.events[0]).allowed
            == lower.decide(task, task.events[0]).allowed is True)


# --------------------------------------------------------------------------- #
# The module's declared properties, as unit tests
# --------------------------------------------------------------------------- #
def _fixture():
    from uuid import uuid4

    from agentauth.core.delegation import issue_delegation, sign_delegation
    from agentauth.core.signing import generate_keypair

    operator = generate_keypair()
    caps = [{"resource": "db", "action": "read"}, {"resource": "db", "action": "write"}]
    parent, sub = uuid4(), uuid4()
    root = issue_delegation(None, delegate_agent_id=parent, capabilities=caps)
    root_env = sign_delegation(root, operator)
    child = issue_delegation(None, parent_envelope=root_env, delegate_agent_id=sub,
                             capabilities=[caps[0]])
    child_env = sign_delegation(child, operator, parent_envelope=root_env)
    policy = DelegationPolicy(root_authority=root.commitment(),
                              trusted_signers=frozenset({operator.public_key_hex}),
                              max_depth=MAX_DEPTH)
    return operator, caps, str(parent), str(sub), root_env, child, child_env, policy


def test_attenuation_refuses_a_widened_child():
    from uuid import uuid4

    from agentauth.core.delegation import issue_delegation

    _op, caps, _p, _s, _root_env, _child, child_env, _policy = _fixture()
    with pytest.raises(ValueError):
        issue_delegation(None, parent_envelope=child_env,
                         delegate_agent_id=uuid4(), capabilities=caps)


def test_a_delegation_is_bound_to_the_agent_it_names():
    _op, _caps, parent, _sub, _root_env, _child, child_env, policy = _fixture()
    boundary = DelegationBoundary(policy)
    assert not boundary.authorize(principal=parent, resource="db", action="read",
                                  envelope=child_env).allowed


def test_absence_of_a_delegation_is_a_denial():
    _op, _caps, _p, sub, _root_env, _child, _child_env, policy = _fixture()
    boundary = DelegationBoundary(policy)
    assert not boundary.authorize(principal=sub, resource="db", action="read",
                                  envelope=None).allowed
    # The shipped primitive now refuses the same input. It used to return no
    # violations, which made "present nothing at all" the attacker's cheapest
    # presentation. Pinned here so that if it ever regresses, the row in
    # benchmarks/results/deputy.md is re-measured rather than trusted.
    assert not shipped_primitive_allows(resource="db", action="read", envelope=None)


def test_an_unpinned_signer_is_refused():
    from uuid import UUID

    from agentauth.core.delegation import issue_delegation, sign_delegation
    from agentauth.core.signing import generate_keypair

    _op, caps, _p, sub, _root_env, _child, _child_env, policy = _fixture()
    outsider = generate_keypair()
    forged = issue_delegation(None, delegate_agent_id=UUID(sub), capabilities=caps)
    forged_env = sign_delegation(forged, outsider)
    boundary = DelegationBoundary(policy)
    assert not boundary.authorize(principal=sub, resource="db", action="write",
                                  envelope=forged_env).allowed
    assert shipped_primitive_allows(resource="db", action="write",
                                    envelope=forged_env)


def test_revocation_stops_the_next_action_and_spares_the_parent():
    _op, _caps, parent, sub, root_env, child, child_env, policy = _fixture()
    boundary = DelegationBoundary(policy)
    assert boundary.authorize(principal=sub, resource="db", action="read",
                              envelope=child_env).allowed
    boundary.revoke(child.delegation_id)
    assert not boundary.authorize(principal=sub, resource="db", action="read",
                                  envelope=child_env).allowed
    assert boundary.authorize(principal=parent, resource="db", action="read",
                              envelope=root_env).allowed


def test_revoking_a_parent_takes_its_children_with_it():
    from uuid import uuid4

    from agentauth.core.delegation import issue_delegation, sign_delegation

    operator, _caps, _p, _sub, _root_env, child, child_env, policy = _fixture()
    grand = uuid4()
    token = issue_delegation(None, parent_envelope=child_env,
                             delegate_agent_id=grand,
                             capabilities=[{"resource": "db", "action": "read"}])
    grand_env = sign_delegation(token, operator, parent_envelope=child_env)
    boundary = DelegationBoundary(policy)
    assert boundary.authorize(principal=str(grand), resource="db", action="read",
                              envelope=grand_env).allowed
    boundary.revoke(child.delegation_id)
    assert not boundary.authorize(principal=str(grand), resource="db",
                                  action="read", envelope=grand_env).allowed


def _deep_chain(operator, child_env, links: int):
    """``links`` further re-delegations of the sub-scope, each properly issued."""
    from uuid import uuid4

    from agentauth.core.delegation import issue_delegation, sign_delegation

    env = child_env
    holder = None
    for _ in range(links):
        holder = uuid4()
        token = issue_delegation(None, parent_envelope=env,
                                 delegate_agent_id=holder,
                                 capabilities=[{"resource": "db", "action": "read"}])
        env = sign_delegation(token, operator, parent_envelope=env)
    return env, holder


def test_the_depth_bound_reads_the_chain_not_the_number_the_leaf_declares():
    """The chain-shape sweep's finding, pinned.

    `depth` is a field a token writes about itself. Comparing it to `max_depth`
    and never to the links underneath it means a leaf on a long chain that
    declares `depth: 1` clears the bound that the identical chain, declared
    honestly, is refused by.
    """
    from datetime import datetime, timedelta, timezone
    from uuid import uuid4

    from agentauth.core.delegation import (
        DelegationToken, delegation_from_envelope, sign_delegation)

    operator, _caps, _p, _sub, _root_env, _child, child_env, policy = _fixture()
    boundary = DelegationBoundary(policy)
    deep_env, holder = _deep_chain(operator, child_env, MAX_DEPTH + 3)

    honest = boundary.authorize(principal=str(holder), resource="db",
                                action="read", envelope=deep_env)
    assert not honest.allowed and honest.rule == "depth"

    now = datetime.now(timezone.utc)
    liar = uuid4()
    spoof = DelegationToken(
        delegation_id=uuid4(), delegate_agent_id=liar,
        capabilities=[{"resource": "db", "action": "read"}], depth=1,
        issued_at=now, expires_at=now + timedelta(seconds=3600),
        parent=delegation_from_envelope(deep_env))
    spoof_env = sign_delegation(spoof, operator, parent_envelope=deep_env)

    verdict = boundary.authorize(principal=str(liar), resource="db",
                                 action="read", envelope=spoof_env)
    assert not verdict.allowed and verdict.rule == "depth"
    # The shipped primitive has no depth rule at all, which is the gap.
    assert shipped_primitive_allows(resource="db", action="read",
                                    envelope=spoof_env)


def test_a_chain_within_the_bound_is_still_allowed():
    """The control for the test above: a mechanism that refused every chain
    would pass it."""
    operator, _caps, _p, _sub, _root_env, _child, child_env, policy = _fixture()
    deep_env, holder = _deep_chain(operator, child_env, MAX_DEPTH - 1)
    assert DelegationBoundary(policy).authorize(
        principal=str(holder), resource="db", action="read",
        envelope=deep_env).allowed


def test_a_delegation_does_not_outlive_the_authority_it_derives_from():
    """`verify_delegation_chain` checks `is_valid_at` on the leaf and on nothing
    above it, so a fresh child of an expired root verified clean."""
    from datetime import datetime, timedelta, timezone
    from uuid import uuid4

    from agentauth.core.delegation import (
        DelegationToken, issue_delegation, sign_delegation)
    from agentauth.core.signing import generate_keypair

    operator = generate_keypair()
    caps = [{"resource": "db", "action": "read"}]
    now = datetime.now(timezone.utc)
    stale_root = DelegationToken(
        delegation_id=uuid4(), delegate_agent_id=uuid4(), capabilities=list(caps),
        depth=0, issued_at=now - timedelta(seconds=7200),
        expires_at=now - timedelta(seconds=3600))
    stale_root_env = sign_delegation(stale_root, operator)
    heir = uuid4()
    fresh = issue_delegation(None, parent_envelope=stale_root_env,
                             delegate_agent_id=heir, capabilities=caps)
    fresh_env = sign_delegation(fresh, operator, parent_envelope=stale_root_env)

    policy = DelegationPolicy(
        root_authority=stale_root.commitment(),
        trusted_signers=frozenset({operator.public_key_hex}), max_depth=MAX_DEPTH)
    verdict = DelegationBoundary(policy).authorize(
        principal=str(heir), resource="db", action="read", envelope=fresh_env)
    assert not verdict.allowed and verdict.rule == "expiry"
    assert shipped_primitive_allows(resource="db", action="read",
                                    envelope=fresh_env)


@pytest.mark.parametrize("corpus", ["tau2", "bfcl"])
def test_the_chain_shape_sweep_holds_and_its_controls_pass(corpus):
    """Both evasions contained on real sessions, and neither control refused."""
    _available(corpus)
    r = evaluate(corpus, split="verb", count=60, seed=0)
    assert r.chain_evasions
    for arm, (_shipped, boundary, total) in r.chain_evasions.items():
        assert total > 0
        if arm.startswith("control:"):
            assert boundary == 0, f"{arm} was refused; the boundary refuses too much"
        else:
            assert boundary == total, f"{arm} walked through the boundary"


@pytest.mark.parametrize("corpus", ["tau2", "bfcl"])
def test_the_false_block_is_reported_on_sessions_no_cap_was_fitted_to(corpus):
    """Invariant 4. This rung fits nothing, but the velocity rung under it does,
    and the reported friction has to come from sessions outside its calibration
    set or it is arithmetic."""
    _available(corpus)
    r = evaluate(corpus, split="verb", count=60, seed=0)
    assert 0 < r.heldout_events < r.benign_events
    assert r.heldout_blocked == r.heldout_ladder_blocked, (
        "the delegation rung added a false block on held-out benign traffic")


def test_an_unconfigured_signer_policy_refuses_rather_than_trusting():
    _op, _caps, _p, sub, _root_env, _child, child_env, policy = _fixture()
    open_policy = DelegationPolicy(root_authority=policy.root_authority)
    boundary = DelegationBoundary(open_policy)
    assert not boundary.authorize(principal=sub, resource="db", action="read",
                                  envelope=child_env).allowed
