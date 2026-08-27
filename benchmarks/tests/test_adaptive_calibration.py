"""The adaptive red-team must calibrate the engines it attacks.

`run_benchmark` gives a calibrated engine one look at clean traffic through
`observe_corpus`. The adaptive path did not, and the omission was invisible
because an uncalibrated engine does not crash, it silently uses a default.
"""
from __future__ import annotations

import pytest

from benchmarks.adaptive import calibrate
from benchmarks.core.engines import build_engines
from benchmarks.core.events import EventLabel
from benchmarks.datasets.base import get_loader

VELOCITY = "task-scope+binding+budget+velocity"
DENSITY = "task-scope+binding+budget+velocity+density"


def _tasks(name: str = "redcode"):
    try:
        return list(get_loader(name).load())
    except Exception as exc:  # pragma: no cover - corpus not fetched
        pytest.skip(f"{name} not available: {exc}")


def test_the_velocity_cap_is_calibrated_rather_than_left_at_its_default():
    """The defect, in the currency that matters.

    Uncalibrated, `VelocityLadderEngine` falls back to ``default_cap = 5``.
    Calibration on RedCode yields **32**. So every adaptive result for that rung
    was produced with a cap 6.4x tighter than the one an operator would set from
    their own logs, which biases containment upward, the direction that flatters
    the system.
    """
    tasks = _tasks()
    engine = build_engines([VELOCITY])[0]
    assert engine._cap is None, "premise stale: the engine now self-calibrates"

    calibrate([engine], tasks, seed=0)
    assert engine._cap is not None, "calibrate() did not reach the velocity rung"
    assert engine._cap != engine.default_cap, (
        f"the calibrated cap equals the default ({engine.default_cap}); this "
        "test can no longer tell a calibrated engine from an uncalibrated one")


def test_the_density_rung_is_not_inert_under_the_adaptive_harness():
    """Without calibration the density has no baseline, abstains on every event,
    and its row is a verbatim copy of its parent's. A row that cannot differ from
    the one above it is not a measurement."""
    tasks = _tasks()
    engine = build_engines([DENSITY])[0]
    assert engine._scorer is None

    calibrate([engine], tasks, seed=0)
    assert engine._scorer is not None, (
        "the density rung would abstain on every event in the adaptive red-team")


def test_calibration_never_shows_an_engine_an_attack_bearing_task():
    """The runner's split, reused: attack-bearing tasks never calibrate anything.

    Calibrating on the corpus about to be attacked would set the policy from the
    attack it is judged against, which is the circularity `heldout.py` exists to
    remove from the friction numbers.
    """
    seen: list = []

    class Spy:
        name = "spy"

        def observe_corpus(self, tasks):
            seen.extend(tasks)

        def decide(self, task, event):  # pragma: no cover - never called here
            raise AssertionError

    calibrate([Spy()], _tasks(), seed=0)
    assert seen, "calibrate() did not call observe_corpus"
    assert not any(
        any(e.label is EventLabel.ATTACK for e in task.events) for task in seen
    ), "an attack-bearing task reached the calibration set"


def test_an_engine_without_the_hook_is_left_alone():
    """Most rungs declare their policy rather than calibrating it, and must pass
    through untouched rather than raising."""
    engines = build_engines(["task-scope", "allow-all"])
    calibrate(engines, _tasks(), seed=0)  # must not raise
    assert all(not hasattr(e, "_cap") for e in engines)
