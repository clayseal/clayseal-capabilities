"""Structural invariants of the enforcement ladder, checked on every corpus.

The ladder's whole claim is that each rung adds authority granularity: a higher
rung contains everything the rung below it contained, and does not pay for that
with new false blocks. Before this file those properties were asserted in prose
in benchmarks/README.md and verified by whichever corpus happened to expose a
violation. RedCode exposed one (connector-substitution passed `task-scope` and
failed `capability-token`, because a path-scoped mandate compiles to an empty
`allowed_resources`); the fixture never would have.

So the invariants are tested directly, per-event rather than in aggregate, on
every dataset that is present. A rate-level check is not enough: two rungs can
report the same containment percentage while disagreeing on which events they
caught, and that disagreement is exactly the defect class we are hunting.
"""
from __future__ import annotations

import pytest

from benchmarks.core.engines import LADDER, build_engines
from benchmarks.core.events import BenchmarkTask, EventLabel
from benchmarks.core.runner import run_benchmark

# Corpora that ship in-repo run always; external ones skip when unfetched.
DATASETS = ["fixture", "redcode", "agentharm", "asb", "bfcl", "agentdojo", "injecagent", "toolemu"]

# `deny-all` is the friction ceiling, not a rung anyone deploys. It is monotone
# by definition and its false-block rate is 100% by design, so both invariants
# below would be trivially satisfied or trivially violated by it.
DEPLOYABLE = [name for name in LADDER if name != "deny-all"]


def _load(name: str):
    from benchmarks.datasets.base import get_loader

    try:
        tasks = get_loader(name).load()
    except (RuntimeError, FileNotFoundError) as exc:
        pytest.skip(f"{name}: {str(exc).splitlines()[0]}")
    if not tasks:
        pytest.skip(f"{name}: loader produced no tasks")
    return tasks


def _decisions(tasks, engine_names):
    """Per-engine map of (task_id, event_index) -> allowed."""
    engines = {e.name: e for e in build_engines() if e.name in engine_names}
    assert set(engines) == set(engine_names), "ladder engine missing from registry"
    out = {}
    for name in engine_names:
        engine = engines[name]
        out[name] = {
            (task.task_id, idx): engine.decide(task, event).allowed
            for task in tasks
            for idx, event in enumerate(task.events)
        }
    return out


@pytest.mark.parametrize("dataset", DATASETS)
def test_containment_is_monotone_up_the_ladder(dataset):
    """No attack event may be blocked by a rung and allowed by a rung above it.

    This is the invariant RedCode broke. Reported per offending event so a
    regression names the exact case rather than a moved percentage.
    """
    tasks = _load(dataset)
    decisions = _decisions(tasks, DEPLOYABLE)

    attack_keys = {
        (task.task_id, idx)
        for task in tasks
        for idx, event in enumerate(task.events)
        if event.label is EventLabel.ATTACK
    }
    if not attack_keys:
        pytest.skip(f"{dataset}: no attack events")

    regressions = []
    for lower, higher in zip(DEPLOYABLE, DEPLOYABLE[1:]):
        for key in attack_keys:
            if not decisions[lower][key] and decisions[higher][key]:
                regressions.append(f"{key[0]}#{key[1]}: {lower} blocked, {higher} allowed")

    assert not regressions, (
        f"{dataset}: containment regressed up the ladder in {len(regressions)} case(s):\n"
        + "\n".join(sorted(regressions)[:10])
    )


@pytest.mark.parametrize("dataset", DATASETS)
def test_higher_rungs_do_not_add_false_blocks(dataset):
    """Friction must stay flat as authority narrows.

    A rung that buys containment by denying legitimate work is not an
    improvement, and on the benign side of these corpora every event is one the
    task's own mandate authorized. Unlike containment this is not a hard
    architectural guarantee, so the assertion is on the rate rather than
    per-event: a higher rung may trade *which* benign events it blocks, but not
    block more of them.
    """
    tasks = _load(dataset)
    benign = [t for t in tasks if any(e.label is EventLabel.BENIGN for e in t.events)]
    if not benign:
        pytest.skip(f"{dataset}: no benign events")

    engines = [e for e in build_engines() if e.name in DEPLOYABLE]
    results = run_benchmark(benign, engines)

    rates = [(name, results[name].false_block_rate) for name in DEPLOYABLE]
    for (lower, lo_rate), (higher, hi_rate) in zip(rates, rates[1:]):
        assert hi_rate <= lo_rate + 1e-9, (
            f"{dataset}: {higher} false-blocks {hi_rate:.1%} vs {lower} {lo_rate:.1%}"
        )


@pytest.mark.parametrize("dataset", DATASETS)
def test_ladder_bounds_hold(dataset):
    """allow-all floors containment at zero; deny-all ceilings friction at one.

    Cheap, but it catches a mislabeled corpus: if `allow-all` ever reports
    non-zero containment, attack events are being counted somewhere they are
    not being decided.
    """
    tasks = _load(dataset)
    results = run_benchmark(tasks, build_engines())

    assert results["allow-all"].attack_prevention_rate == 0.0
    assert results["allow-all"].false_block_rate == 0.0
    if results["deny-all"].n_attack:
        assert results["deny-all"].attack_prevention_rate == 1.0
    if results["deny-all"].n_benign:
        assert results["deny-all"].false_block_rate == 1.0


# --------------------------------------------------------------------------- #
# Argument binding: what it is for, and what it must not block
# --------------------------------------------------------------------------- #
def _bound_task(action: str, args: dict) -> BenchmarkTask:
    from benchmarks.core.events import BenchmarkEvent

    return BenchmarkTask(
        task_id="bound",
        summary="query invoices",
        events=[BenchmarkEvent(
            event_id="e1", tool_name="list_invoices", resource="invoices",
            action=action, label=EventLabel.BENIGN, args=args,
        )],
        mandate={
            "grant_id": "bound-grant", "issuer": "did:clayseal:test",
            "issued_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2027-01-01T00:00:00+00:00",
            "allowed_actions": [action], "allowed_resources": ["invoices"],
        },
        capabilities=[{"resource": "invoices", "action": action}],
        allowed_tools={"list_invoices"},
        authorized_args={"list_invoices": [{"status": "pending"}]},
    )


def test_unfiltered_read_of_a_bound_tool_is_allowed():
    """`list_invoices()` where `list_invoices(status="pending")` was authorized.

    Binding exists to stop an effect being redirected, and an empty argument set
    redirects nothing. This was the only source of false blocks in the whole
    ATIF corpus (2 of 282 benign events).
    """
    engine = next(e for e in build_engines() if e.name == "task-scope+binding")
    task = _bound_task("read", {})
    assert engine.decide(task, task.events[0]).allowed


def test_mutated_read_arguments_are_still_blocked():
    """The exemption is for ABSENT arguments, not different ones."""
    engine = next(e for e in build_engines() if e.name == "task-scope+binding")
    task = _bound_task("read", {"status": "paid"})
    assert not engine.decide(task, task.events[0]).allowed


def test_argument_less_effects_are_still_blocked():
    """An effect verb gets no exemption: a payment with no arguments is not a
    broadened query, and reversibility is what justifies the exemption."""
    engine = next(e for e in build_engines() if e.name == "task-scope+binding")
    task = _bound_task("transfer", {})
    assert not engine.decide(task, task.events[0]).allowed


# --------------------------------------------------------------------------- #
# Velocity: the cap must not be a function of the label
# --------------------------------------------------------------------------- #
def _task(task_id, benign_effects, attack_effects):
    from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, EventLabel

    def _ev(i, label):
        return BenchmarkEvent(
            event_id=f"{task_id}-{i}", tool_name="send_email",
            resource="mcp:tool:send_email", action="send", label=label)

    events = [_ev(i, EventLabel.BENIGN) for i in range(benign_effects)]
    events += [_ev(benign_effects + i, EventLabel.ATTACK)
               for i in range(attack_effects)]
    return BenchmarkTask(
        task_id=task_id, summary="g", events=events,
        mandate={"allowed_resources": ["mcp:tool:send_email"]},
        capabilities=[{"resource": "mcp:tool:send_email", "action": "send"}],
        allowed_tools={"send_email"})


def test_the_velocity_cap_never_reads_the_task_being_judged():
    """The defect this replaces.

    The first version set the cap from the task's own benign effect count. On
    SLEIGHT, RedCode and ASB every attack-bearing task has zero benign effects,
    so each was handed cap=1 and the reported containment was the label read
    back. Two tasks with identical clean context must get identical caps
    regardless of how much attack traffic they carry.
    """
    from benchmarks.core.engines import VelocityLadderEngine

    corpus = [_task("clean-1", 6, 0), _task("clean-2", 4, 0),
              _task("attacked", 0, 12)]
    engine = VelocityLadderEngine()
    engine.observe_corpus(corpus)
    cap = engine._cap

    # The same corpus with a far heavier attack must not move the cap.
    heavier = [_task("clean-1", 6, 0), _task("clean-2", 4, 0),
               _task("attacked", 0, 400)]
    other = VelocityLadderEngine()
    other.observe_corpus(heavier)
    assert other._cap == cap, (
        "the cap moved when only attack traffic changed; it is label-derived"
    )


def test_the_velocity_cap_sits_above_clean_traffic():
    """A cap below normal volume is a false-block generator, not a defense."""
    from benchmarks.core.engines import VelocityLadderEngine

    corpus = [_task(f"clean-{i}", vol, 0) for i, vol in enumerate([1, 2, 3, 9, 30])]
    engine = VelocityLadderEngine()
    engine.observe_corpus(corpus)
    assert engine._cap >= 30
