"""Invariants for pattern generalisation of a grant.

Six headline numbers have been withdrawn in this project, and the two that would
most easily reappear here are a policy parameter derived from the attack label
and a false-block rate measured on its own calibration set. The namespace level
is a learned policy, so both failure modes are live and both are tested rather
than argued.
"""
from __future__ import annotations

import pytest

from benchmarks.core.engines import LADDER, build_engines
from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, EventLabel
from benchmarks.core.heldout import hold_out_corpus
from benchmarks.core.patterns import (
    EVERYTHING,
    EXACT,
    NAMESPACE,
    UP1,
    UP2,
    calibration_indices,
    generalize_corpus,
    namespace_from,
    path_patterns,
    resource_patterns,
    tool_patterns,
)
from benchmarks.core.runner import _calibration_split, run_benchmark

DEPLOYABLE = [n for n in LADDER if n not in ("deny-all", "allow-all")]
DATASETS = ["fixture", "redcode", "agentharm", "asb", "bfcl", "injecagent", "toolemu"]


def _load(name: str):
    from benchmarks.datasets.base import get_loader

    try:
        tasks = get_loader(name).load()
    except (RuntimeError, FileNotFoundError) as exc:
        pytest.skip(f"{name}: {str(exc).splitlines()[0]}")
    if not tasks:
        pytest.skip(f"{name}: loader produced no tasks")
    return tasks


# --------------------------------------------------------------------------- #
# Pattern arithmetic
# --------------------------------------------------------------------------- #
def test_two_segments_up_never_means_everything():
    """The floor that stops level 2 from silently becoming level 4.

    ``book_reservation`` has two segments; dropping both leaves the empty prefix,
    which matches every tool that exists. Without ``keep_min`` the curve would
    show a collapse at level 2 that is an artefact of the arithmetic rather than
    a property of the grant.
    """
    assert "*" not in tool_patterns("book_reservation", UP2)
    assert tool_patterns("book_reservation", UP2) == {"book_reservation", "book_*"}
    assert "*" in tool_patterns("book_reservation", EVERYTHING)


def test_levels_are_cumulative_on_every_dimension():
    for fn, sample in ((tool_patterns, "get_reservation_details"),
                       (resource_patterns, "mcp:tool:get_reservation_details"),
                       (path_patterns, "/app/src/main.py")):
        prev = fn(sample, EXACT)
        for level in (UP1, UP2, NAMESPACE, EVERYTHING):
            cur = fn(sample, level)
            assert prev <= cur, f"{fn.__name__} not cumulative at level {level}"
            prev = cur


def test_resource_namespace_does_not_cross_schemes():
    """No level below `everything` may emit a wildcard that leaves the scheme.

    Connector substitution is a documented attack class in this codebase and it
    lives exactly on this boundary: a grant for the agent's MCP tools that also
    covered network destinations would authorize the exfiltration target. A bare
    ``mcp:tool:*`` is refused too — it makes the capability rung a pass-through,
    which broke ladder monotonicity on ASB.
    """
    for level in (UP1, UP2, NAMESPACE):
        pats = resource_patterns("mcp:tool:send_email", level)
        assert "mcp:tool:*" not in pats
        assert not any(p == "*" or p.startswith("net") for p in pats)
    assert "*" in resource_patterns("mcp:tool:send_email", EVERYTHING)


# --------------------------------------------------------------------------- #
# Invariant 4: a calibrated policy is scored on data it did not see
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("dataset", DATASETS)
def test_namespace_calibration_matches_the_runner_split(dataset):
    """Every task a namespace was learned from is a task the runner does not score.

    ``calibration_indices`` reproduces ``runner._calibration_split`` positionally
    rather than re-deriving it. If the two ever drift, a namespace could be
    learned from a task that is then scored against it, which is the
    measured-on-its-own-calibration-set defect in a new costume.
    """
    tasks = _load(dataset)
    calib_idx, _ = calibration_indices(tasks, seed=0)
    runner_calib, runner_scored = _calibration_split(tasks, 0)
    if not calib_idx:
        # Degenerate corpus: fewer than two clean tasks, so nothing is held out
        # and nothing may be learned.
        assert runner_calib is runner_scored or len(runner_calib) == len(tasks)
        return
    scored_ids = {id(t) for t in runner_scored}
    for i in calib_idx:
        assert id(tasks[i]) not in scored_ids, (
            f"{tasks[i].task_id} both taught the namespace and was scored by it")


# --------------------------------------------------------------------------- #
# Invariant 1: a policy parameter must not move when only attack traffic changes
# --------------------------------------------------------------------------- #
def _task(tid, tools, label=EventLabel.BENIGN):
    events = [
        BenchmarkEvent(event_id=f"{tid}-{i}", tool_name=t,
                       resource=f"mcp:tool:{t}", action="read", label=label)
        for i, t in enumerate(tools)
    ]
    return BenchmarkTask(
        task_id=tid, summary=tid, events=events, allowed_tools=set(tools),
        capabilities=[{"resource": f"mcp:tool:{t}", "action": "read"} for t in tools],
        mandate={"grant_id": tid, "allowed_resources": [f"mcp:tool:{t}" for t in tools]},
        meta={"goal_kind": "bucket"},
    )


def test_namespace_does_not_move_when_attack_traffic_changes():
    clean = [_task("c1", ["get_user_details"]), _task("c2", ["get_order_details"]),
             _task("c3", ["book_reservation"]), _task("c4", ["cancel_reservation"])]
    quiet = clean + [_task("a1", ["exfiltrate_all"], EventLabel.ATTACK)]
    loud = clean + [_task("a1", ["exfiltrate_all"], EventLabel.ATTACK),
                    _task("a2", ["wipe_disk"], EventLabel.ATTACK),
                    _task("a3", ["post_credentials"], EventLabel.ATTACK)]
    ns_quiet = namespace_from(quiet, calibration_indices(quiet, 0)[0])
    ns_loud = namespace_from(loud, calibration_indices(loud, 0)[0])
    assert ns_quiet.tools_for("bucket") == ns_loud.tools_for("bucket")
    assert "exfiltrate_all" not in ns_quiet.tools_for("bucket")
    assert "wipe_disk" not in ns_loud.tools_for("bucket")


def test_namespace_refuses_to_learn_from_an_attack_bearing_task():
    tasks = [_task("c1", ["get_user"]), _task("c2", ["get_order"]),
             _task("a1", ["exfiltrate"], EventLabel.ATTACK)]
    with pytest.raises(AssertionError):
        namespace_from(tasks, [0, 2])


# --------------------------------------------------------------------------- #
# Level 0 is the identity: the sweep reproduces the shipped system
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("dataset", DATASETS)
def test_level_zero_is_the_identity(dataset):
    tasks = _load(dataset)
    assert generalize_corpus(tasks, tool_level=EXACT, path_level=EXACT) is tasks
    held_plain, n_plain = hold_out_corpus(tasks, seed=0)
    held_zero, n_zero = hold_out_corpus(tasks, seed=0, tool_level=0, path_level=0)
    assert n_plain == n_zero
    for a, b in zip(held_plain, held_zero):
        assert a.allowed_tools == b.allowed_tools
        assert a.tool_patterns is None and b.tool_patterns is None
        assert a.mandate == b.mandate


# --------------------------------------------------------------------------- #
# Invariant 3: no lower rung may contain an attack event a higher rung allows
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("dataset", ["fixture", "redcode", "asb", "toolemu"])
@pytest.mark.parametrize("level", [UP1, UP2, NAMESPACE])
def test_ladder_stays_monotone_under_a_pattern_grant(dataset, level):
    """Generalising the grant must not reorder the ladder.

    A pattern grant is applied at the scope rung, and the rungs below it read the
    same fields. If a rung that reads ``allowed_tools`` and one that reads
    ``allowed_resources`` disagree about what a pattern covers, a lower rung can
    contain an attack the top rung allows, which is the defect RedCode exposed
    for connector substitution.
    """
    tasks = generalize_corpus(_load(dataset), tool_level=level, path_level=level)
    engines = {e.name: e for e in build_engines() if e.name in DEPLOYABLE}
    order = [n for n in LADDER if n in engines]
    offenders = []
    for task in tasks:
        for event in task.events:
            if event.label is not EventLabel.ATTACK:
                continue
            allowed = [engines[n].decide(task, event).allowed for n in order]
            for i in range(len(order) - 1):
                if not allowed[i] and allowed[i + 1]:
                    offenders.append((task.task_id, event.event_id,
                                      order[i], order[i + 1]))
    assert not offenders, offenders[:5]


# --------------------------------------------------------------------------- #
# Invariant 2: shuffling events inside a task must not move containment
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("dataset", ["redcode", "asb", "toolemu"])
def test_containment_is_order_independent_under_patterns(dataset):
    import random

    tasks = _load(dataset)
    shuffled = []
    rng = random.Random(7)
    for t in tasks:
        events = list(t.events)
        rng.shuffle(events)
        shuffled.append(BenchmarkTask(**{**vars(t), "events": events}))
    # Fresh engines per run. TaskScopeEngine caches a compiled scope by task_id,
    # and a pattern grant changes the scope while the id stays the same, so a
    # reused engine silently scores level N with level 0's scope. That is a real
    # trap for anyone sweeping levels in a loop, and it cost this test a false
    # failure before it cost a measurement one.
    for level in (EXACT, UP1, NAMESPACE):
        a = run_benchmark(generalize_corpus(tasks, tool_level=level, path_level=level),
                          [e for e in build_engines() if e.name in DEPLOYABLE]
                          )[DEPLOYABLE[-1]]
        b = run_benchmark(generalize_corpus(shuffled, tool_level=level, path_level=level),
                          [e for e in build_engines() if e.name in DEPLOYABLE]
                          )[DEPLOYABLE[-1]]
        assert abs(a.attack_prevention_rate - b.attack_prevention_rate) < 1e-9, level


# --------------------------------------------------------------------------- #
# Invariant 6: task ids stay unique through the transform
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("dataset", DATASETS)
def test_task_ids_stay_unique(dataset):
    tasks = generalize_corpus(_load(dataset), tool_level=NAMESPACE, path_level=NAMESPACE)
    ids = [t.task_id for t in tasks]
    assert len(ids) == len(set(ids))


# --------------------------------------------------------------------------- #
# Generalisation is monotone in the level: friction may only fall, containment
# may only fall. A curve that is not monotone is measuring something else.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("dataset", ["fixture", "redcode", "bfcl"])
def test_containment_is_non_increasing_in_the_level(dataset):
    tasks = _load(dataset)
    rates = []
    for level in (EXACT, UP1, UP2, NAMESPACE, EVERYTHING):
        r = run_benchmark(generalize_corpus(tasks, tool_level=level, path_level=level),
                          [e for e in build_engines() if e.name in DEPLOYABLE]
                          )[DEPLOYABLE[-1]]
        if r.n_attack:
            rates.append(r.attack_prevention_rate)
    for a, b in zip(rates, rates[1:]):
        assert b <= a + 1e-9, rates
