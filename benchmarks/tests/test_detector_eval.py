"""Benchmark integration: the detector eval converts tasks to trajectories and
scores trajectory-level containment vs conformal false-block."""
from __future__ import annotations

from benchmarks.core.detector_eval import run_detector_benchmark, task_to_trajectories
from benchmarks.datasets.fixture import FixtureLoader


def test_task_to_trajectories_splits_benign_and_attack():
    task = next(t for t in FixtureLoader().load() if t.task_id == "triage-inbox")
    benign, attack = task_to_trajectories(task)
    assert len(benign.actions) == 1              # one benign read
    assert len(attack.actions) == 3              # benign + two injected steps
    assert attack.goal.query_id == task.task_id


def test_detector_benchmark_runs_on_fixture():
    # Tiny corpus, so this asserts the pipeline wires end to end and stays inside
    # its guarantees, not a headline number (real numbers come from AgentDojo).
    result = run_detector_benchmark(FixtureLoader().load(), train_frac=0.5)
    s = result.summary()
    assert s["scorer"] == "ngram"
    assert 0.0 <= s["containment_rate"] <= 1.0
    assert result.false_block_rate <= result.alpha + 0.5  # loose on 2 test trajectories
