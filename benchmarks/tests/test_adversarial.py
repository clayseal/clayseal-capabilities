"""Phase 2 tests: adversarial synthesis + per-attack-class leaderboard."""
from __future__ import annotations

from benchmarks.adversarial.attacks import ATTACK_CLASSES, synthesize
from benchmarks.core.engines import build_engines
from benchmarks.core.leaderboard import run_leaderboard
from benchmarks.core.events import EventLabel
from benchmarks.datasets.fixture import FixtureLoader


def test_synthesize_produces_labeled_attack_variants():
    variants = synthesize(FixtureLoader().load(), seed=0)
    assert variants
    classes = {v.attack_class for v in variants}
    # The fixture exercises payments (splitting), reads (exfil), and tools.
    assert {"argument-tampering", "unauthorized-tool", "fragmented-overspend"} <= classes
    for v in variants:
        assert any(e.label is EventLabel.ATTACK for e in v.task.events)
        assert all(e.label is EventLabel.BENIGN
                   for e in v.task.events[: -sum(e.label is EventLabel.ATTACK
                                                 for e in v.task.events)])


def test_fragmented_overspend_only_from_budgeted_tasks():
    tasks = FixtureLoader().load()
    variants = synthesize(tasks, classes=["fragmented-overspend"], seed=0)
    # Only the payroll task carries a value budget, so exactly one variant.
    assert len(variants) == 1
    assert variants[0].task.task_id.startswith("payroll")


def test_leaderboard_full_stack_dominates_and_no_false_blocks():
    tasks = FixtureLoader().load()
    boards = run_leaderboard(tasks, seed=0)
    full = boards["task-scope+binding+budget"]
    naive = boards["tool-allowlist"]
    # The full stack contains at least as many attacks overall as naive RBAC.
    assert full.overall_containment >= naive.overall_containment
    # Real engines never block a benign step.
    for name in ("tool-allowlist", "capability-token", "task-scope",
                 "task-scope+binding", "task-scope+binding+budget"):
        assert boards[name].false_block_rate == 0.0, name
    # allow-all contains nothing; deny-all contains everything.
    assert boards["allow-all"].overall_containment == 0.0
    assert boards["deny-all"].overall_containment == 1.0


def test_all_attack_classes_registered():
    assert len(ATTACK_CLASSES) == 8
    assert "in-scope-burst" in ATTACK_CLASSES


def test_in_scope_burst_evades_floor_by_construction():
    from benchmarks.adversarial.attacks import synthesize
    from benchmarks.core.engines import build_engines
    from benchmarks.core.events import EventLabel

    tasks = FixtureLoader().load()
    variants = synthesize(tasks, classes=["in-scope-burst"], seed=0)
    assert variants  # at least the read-bearing fixture tasks produce a burst
    floor = build_engines(["task-scope+binding+budget"])[0]
    for v in variants:
        # Every burst event reuses an authorized read; the floor must allow them.
        for e in v.task.events:
            if e.label is EventLabel.ATTACK:
                assert floor.decide(v.task, e).allowed, "burst should evade the floor"


def test_atif_loader_produces_real_long_trajectories():
    from benchmarks.datasets.atif import AtifLoader
    try:
        tasks = AtifLoader().load()
    except RuntimeError:
        import pytest
        pytest.skip("ATIF corpus not present")
    assert len(tasks) >= 20
    assert max(t.counts()[0] for t in tasks) >= 15  # real long trajectories


def test_delegated_trust_and_ensemble():
    import random
    from agentauth.capabilities.monitor import NGramScorer, TrajectoryDetector
    from agentauth.capabilities.monitor.scoring.ensemble import EnsembleScorer
    from agentauth.capabilities.monitor.training.synth_corpus import generate, inject_delegated_trust

    benign = generate(800, seed=3)
    det = TrajectoryDetector(scorer=EnsembleScorer([NGramScorer(), NGramScorer()]), alpha=0.02)
    det.fit(benign)
    rng = random.Random(0)
    caught = 0
    trials = generate(40, seed=9)
    for t in trials:
        if det.assess(inject_delegated_trust(t, rng)).blocked:
            caught += 1
    assert caught == len(trials)  # security-surface write from untrusted summary
