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
# EVERY registered corpus, not a hand-kept list. The list was eight names while
# the registry held nineteen, and the corpus that violated the order-invariance
# assertion below (SLEIGHT, by 29.5 points) was one of the eleven it omitted. An
# invariant that does not cover a corpus is not protecting it.
def _all_datasets() -> list[str]:
    from benchmarks.datasets.base import available_datasets

    return sorted(available_datasets())


DATASETS = _all_datasets()

# `deny-all` is the friction ceiling, not a rung anyone deploys. It is monotone
# by definition and its false-block rate is 100% by design, so both invariants
# below would be trivially satisfied or trivially violated by it.
# The deterministic ladder stops at the budget rung.
#
# Velocity stays in the tree and is NOT scored here. Measured across all nineteen
# corpora, it contributes zero containment on every one of them and its only
# effects are artifacts: it adds 1.94% false blocks on ATIF and 0.03% on tau2 for
# nothing in return, and on SLEIGHT it reports 61 extra points of "containment"
# that are transcript length rather than the attack. That last number swings 29.5
# points when the events are shuffled, which is the order-invariance assertion
# failing outright.
#
# Its containment claim rests on benchmarks/burst.py, which supplies the burst
# none of these corpora contains and measures it against a held-out false-alarm
# rate. That is the honest place for it.
DEPLOYABLE = [name for name in LADDER
              if name not in ("deny-all", "task-scope+binding+budget+velocity")]


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


# Ladder order for the per-event monotonicity check, cheapest rung first.
LADDER_ORDER = [
    "tool-allowlist",
    "capability-token",
    "task-scope",
    "task-scope+binding",
    "task-scope+binding+budget",
    "task-scope+binding+budget+velocity",
]


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
    # Containment measured over the WHOLE corpus, since `benign` above drops the
    # attack-only tasks a rung might be earning its friction on.
    full = run_benchmark(tasks, [e for e in build_engines() if e.name in DEPLOYABLE])

    rates = [(n, results[n].false_block_rate, full[n].attack_prevention_rate)
             for n in DEPLOYABLE]
    for (lower, lo_fb, lo_c), (higher, hi_fb, hi_c) in zip(rates, rates[1:]):
        if hi_fb <= lo_fb + 1e-9:
            continue
        # A rung may add friction ONLY if it also adds containment. Trading 1% of
        # benign traffic for 98% of the attacks is the ladder working, and
        # Mind2Web-SC does exactly that at the capability rung because the naive
        # rung below it is a no-op there.
        #
        # What this assertion is really for is a rung that costs friction and
        # returns nothing, which is what the velocity rung did on ATIF: +1.94%
        # false blocks for +0.0% containment, before it was removed from the
        # scored ladder.
        assert hi_c > lo_c + 1e-9, (
            f"{dataset}: {higher} false-blocks {hi_fb:.1%} vs {lower} {lo_fb:.1%} "
            f"and adds no containment ({hi_c:.1%} vs {lo_c:.1%})"
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


# --------------------------------------------------------------------------- #
# Stateful rungs must not depend on how a loader happened to order events
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("dataset", DATASETS)
def test_stateful_rungs_are_insensitive_to_event_order(dataset):
    """The general form of a bug that produced a headline number.

    Velocity and the budgets accumulate across a task. If a loader concatenates
    two sessions into one task, the first session's events consume the second's
    budget, and the layer looks like it is containing attacks when it is only
    charging them for arriving late.

    That is exactly what AgentHarm did: benign variant then harmful twin, in one
    trajectory, giving +8.0 points of containment at zero false-block cost. The
    tell is order sensitivity, so this asserts on it directly. Shuffling events
    inside a task must not move either rate.

    A corpus that genuinely records one ordered session is still fine here,
    because within a real session the stateful rungs see the same events; what
    fails is a task whose order carries the label.
    """
    import random
    from copy import copy

    tasks = _load(dataset)
    if not tasks:
        pytest.skip(f"{dataset}: no tasks")

    engines = [e for e in build_engines() if e.name in DEPLOYABLE]
    base = run_benchmark(tasks, engines)

    rnd = random.Random(20260808)
    shuffled = []
    for task in tasks:
        clone = copy(task)
        events = list(task.events)
        rnd.shuffle(events)
        clone.events = events
        shuffled.append(clone)
    after = run_benchmark(shuffled, [e for e in build_engines() if e.name in DEPLOYABLE])

    for name in DEPLOYABLE:
        assert after[name].attack_prevention_rate == pytest.approx(
            base[name].attack_prevention_rate, abs=1e-9), (
            f"{dataset}/{name}: containment depends on event order "
            f"({100*base[name].attack_prevention_rate:.1f}% -> "
            f"{100*after[name].attack_prevention_rate:.1f}%); a stateful rung is "
            f"reading the loader's layout"
        )
        assert after[name].false_block_rate == pytest.approx(
            base[name].false_block_rate, abs=1e-9), (
            f"{dataset}/{name}: false-block depends on event order "
            f"({100*base[name].false_block_rate:.1f}% -> "
            f"{100*after[name].false_block_rate:.1f}%)"
        )


@pytest.mark.parametrize("dataset", DATASETS)
def test_no_lower_rung_contains_what_a_higher_rung_allows(dataset):
    """Monotone containment, asserted per EVENT rather than per rate.

    The rate-level assertion above passes while individual events regress, and
    SLEIGHT proved it: the naive `tool-allowlist` rung contained four attacks
    the full stack allowed, because a task whose scope is resource-shaped never
    re-asked whether the tool itself was granted. A ladder that is monotone only
    in aggregate is not a ladder.
    """
    tasks = _load(dataset)
    if not tasks:
        pytest.skip(f"{dataset}: no tasks")
    engines = build_engines()
    by_name = {e.name: e for e in engines}
    order = [n for n in LADDER_ORDER if n in by_name]
    for e in by_name.values():
        obs = getattr(e, "observe_corpus", None)
        if obs:
            obs(tasks)

    escapes = []
    for task in tasks:
        for event in task.events:
            if event.label is not EventLabel.ATTACK:
                continue
            blocked_at = [n for n in order if not by_name[n].decide(task, event).allowed]
            if not blocked_at:
                continue
            first = order.index(blocked_at[0])
            for n in order[first:]:
                if by_name[n].decide(task, event).allowed:
                    escapes.append((event.event_id, blocked_at[0], n))
    assert not escapes[:5], (
        f"{dataset}: {len(escapes)} attack events a lower rung contains and a "
        f"higher rung allows, e.g. {escapes[:3]}"
    )


@pytest.mark.parametrize("dataset", DATASETS)
def test_task_ids_are_unique(dataset):
    """Stateful engines key per-task state on the id.

    RedCode's `Index` repeats across source files, so 324 of its 768 tasks shared
    an id with another task and two unrelated tasks shared one budget ledger and
    one rate window. A collision is a silent measurement error: it cannot fail
    loudly, it just makes one task's history count against another's.
    """
    from collections import Counter

    tasks = _load(dataset)
    if not tasks:
        pytest.skip(f"{dataset}: no tasks")
    counts = Counter(t.task_id for t in tasks)
    dupes = {k: v for k, v in counts.items() if v > 1}
    assert not dupes, (
        f"{dataset}: {sum(v - 1 for v in dupes.values())} duplicate task ids, "
        f"e.g. {list(dupes.items())[:3]}"
    )


# --------------------------------------------------------------------------- #
# A false-block number must be a measurement, not an identity
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("dataset", DATASETS)
def test_a_benign_derived_grant_is_declared_or_held_out(dataset):
    """Thirteen loaders build a task's grant from its own benign events.

    On six corpora the grant IS the benign side exactly (tau2, BFCL, ATIF,
    InjecAgent, ToolEmu, ASB at 100% of tasks, AgentHarm at 50%), so no benign
    event can fall outside its own grant and 0.00% follows by arithmetic. Our
    strongest published claim, zero false blocks across 18,356 benign events, is
    a tautology at the scope rung.

    The number is still worth reporting, because it says the enforcement layer
    adds no friction beyond the mandate. It is not worth reporting ALONE, so the
    scoreboard carries a held-out column beside it, and this asserts the
    machinery that produces it still applies wherever the grant is circular.
    """
    from benchmarks.core.heldout import _grant_is_benign_side, hold_out_corpus

    tasks = _load(dataset)
    if not tasks:
        pytest.skip(f"{dataset}: no tasks")
    circular = [t for t in tasks if _grant_is_benign_side(t)]
    if not circular:
        return

    from benchmarks.core.heldout import circular_unsplittable

    held, corrected = hold_out_corpus(tasks, seed=0)
    if not corrected:
        # A task with one benign event cannot be split. Then no held-out number
        # exists and the granted one must be declared unscoreable instead.
        assert circular_unsplittable(tasks) == len(circular), (
            f"{dataset}: {len(circular)} circular grants, none held out and not "
            f"all unsplittable; the false-block number would be an identity"
        )
        return
    # Attack events must be untouched: only the friction side may change.
    before = sum(1 for t in tasks for e in t.events if e.label is EventLabel.ATTACK)
    after = sum(1 for t in held for e in t.events if e.label is EventLabel.ATTACK)
    assert before == after, "holding out the mandate changed the attack denominator"


def test_holding_out_a_mandate_narrows_it_rather_than_widening_it():
    """A held-out grant must never admit MORE than the original, or the
    containment number would move for the wrong reason."""
    from benchmarks.core.heldout import hold_out_mandate

    tasks = _load("tau2")
    if not tasks:
        pytest.skip("tau2 unavailable")
    checked = 0
    for task in tasks[:200]:
        held = hold_out_mandate(task, seed=0)
        if held is None:
            continue
        checked += 1
        original = set(task.mandate.get("allowed_resources") or ())
        narrowed = set(held.mandate.get("allowed_resources") or ())
        assert narrowed <= original
        assert set(held.allowed_tools) <= set(task.allowed_tools)
    assert checked > 0


# --------------------------------------------------------------------------- #
# Does the mechanism have a runtime input?
# --------------------------------------------------------------------------- #
def test_the_twin_corridor_now_has_a_runtime_reference():
    """The corridor was benchmark-only and now is not.

    Its SLEIGHT containment is 94.4%, and every point of it comes from
    `assess(reference=benign_twin)`. Exactly one caller supplies a reference and
    it is the benchmark harness; `SessionBroker._behavioral` calls `assess` with
    none. So the shipped system scores the population tiers only, 0 to 5.6%.

    If a live caller ever does supply one, this test should fail and the number
    should be requoted, which is the point of asserting it rather than writing
    it in a document. See benchmarks/results/runtime_inputs.md.
    """
    import inspect

    from agentauth.capabilities import broker

    source = inspect.getsource(broker.SessionBroker)
    # WIRED. The reference is now the agent's own DECLARATION rather than a past
    # clean run, which is an object a deployment has because the agent produces
    # it. See python/tests/test_commit_then_reveal.py.
    assert "reference=self.declared_plan" in source
    # And it stays opt-in: no declaration, no corridor, so every existing
    # number is unchanged.
    assert "declared_plan: Trajectory | None = None" in source


def test_the_delegation_rung_has_a_live_principal():
    """The delegation boundary contains 100% and now has an input.

    Unlike the twin corridor this is a WIRING gap rather than an information
    gap: any multi-agent orchestrator knows which sub-agent issued a call, and
    `Action.meta` can carry it. Until something does, the number is "measured,
    pending integration" and must not be quoted as deployed.
    """
    import inspect

    from agentauth.capabilities import broker

    source = inspect.getsource(broker)
    # WIRED. The acting principal is read from `action.meta["principal"]` and
    # checked before anything else in the floor. See
    # python/tests/test_broker_delegation.py.
    assert '"principal"' in source
    assert "delegation: Any | None = None" in source


def test_the_flow_mechanism_does_have_a_live_input():
    """The contrast case, so the check is not read as 'nothing is deployable'.

    The broker does not see tool outputs, but the live harness intercepts every
    tool result and calls `observe_output`. That is an integration point a
    deployment can build, which is what separates this from the corridor.
    """
    # Read the source rather than importing it: the live harness needs the
    # agentdojo package, which is an optional benchmark extra.
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1]
              / "live" / "broker_defense.py").read_text()
    assert "def observe_output" in source
    assert "observe_output(result" in source
