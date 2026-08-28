"""Synthesized corpora manufacture the signal they are used to measure.

`adequacy.py` says 0 of 11 corpora can evaluate a provenance layer. The standard
repair, synthesize attacks into the benign corpora, appears to fix that and
does not: an appended attack runs at the end of a trajectory, by which point the
session has ingested external content, so it is taint-derived almost by
construction. The gap that results is positional, not semantic.

These tests pin both the artifact and the fix, on real corpora rather than
fixtures, because the artifact is a property of session shape.
"""
import pytest

from benchmarks.adequacy import profile
from benchmarks.adversarial.attacks import synthesize
from benchmarks.core.detector_eval import task_to_trajectories
from benchmarks.core.opmetrics import partial_auc
from benchmarks.datasets.base import get_loader

#: Below this, the statistics below are not measuring anything.
#:
#: `fetch_corpora.sh` copies a five-trace FIXTURE for ToolEmu when the real
#: assets are absent, which is the honest fallback for a corpus that cannot be
#: downloaded. The loader then succeeds, so the `except` below never fires, and
#: the tests went on to assert a taint gap under 0.05 over five samples. In CI
#: that read 0.40 and failed the nightly job; locally, with 116 real tasks, it
#: reads -0.0007 and passes. Neither number was wrong — one of them was noise
#: from an n nobody checked.
_MIN_TASKS = 30


def _load(corpus, n=300):
    try:
        tasks = list(get_loader(corpus).load())[:n]
    except Exception:
        pytest.skip(f"{corpus} unavailable")
    if len(tasks) < _MIN_TASKS:
        pytest.skip(
            f"{corpus}: {len(tasks)} tasks, below the {_MIN_TASKS} these "
            f"statistics need. This is the fixture fallback, not the corpus.")
    return tasks


def _length_auc(tasks, variants):
    by_id = {t.task_id: t for t in tasks}
    bl, al = [], []
    for v in variants:
        src = by_id.get(v.task.task_id.split("::")[0])
        if src is None:
            continue
        b, _ = task_to_trajectories(src)
        _x, a = task_to_trajectories(v.task)
        if b.actions:
            bl.append(float(len(b.actions)))
        if a.actions:
            al.append(float(len(a.actions)))
    if not al or not bl:
        pytest.skip("no comparable variants")
    auc = partial_auc(bl, al, 1.0, standardized=False)
    return max(auc, 1 - auc)


def test_appending_makes_length_the_label_on_short_sessions():
    """BFCL's median session is one event, so appending is a perfect classifier."""
    tasks = _load("bfcl")
    assert _length_auc(tasks, synthesize(tasks, seed=0)) > 0.95


def test_length_matched_synthesis_removes_the_length_label():
    tasks = _load("bfcl")
    auc = _length_auc(tasks, synthesize(tasks, seed=0, length_matched=True))
    assert auc == pytest.approx(0.5, abs=0.02), auc


@pytest.mark.parametrize("corpus", ["tau2", "toolemu", "atif"])
def test_appending_manufactures_a_taint_gap(corpus):
    """The artifact that looks like a result.

    An appended attack is always late, and late actions are taint-derived, so
    the gap reads as a provenance channel. Measured at +15 to +22 points.
    """
    tasks = _load(corpus, 400)
    p = profile(corpus, tasks + [v.task for v in synthesize(tasks, seed=0)])
    assert p["taint_gap"] is not None
    assert p["taint_gap"] > 0.10, p["taint_gap"]


@pytest.mark.parametrize("corpus", ["tau2", "toolemu", "atif"])
def test_length_matched_synthesis_closes_the_taint_gap(corpus):
    """And closing it reveals there was no provenance signal to begin with."""
    tasks = _load(corpus, 400)
    p = profile(corpus, tasks + [v.task
                                 for v in synthesize(tasks, seed=0,
                                                     length_matched=True)])
    assert abs(p["taint_gap"]) < 0.05, p["taint_gap"]


def test_short_sessions_are_dropped_rather_than_appended():
    """No silent fallback.

    Falling back to appending when a session is too short would reintroduce the
    shortcut on exactly the sessions where it is strongest. The cost is volume,
    and the cost is the correct trade.
    """
    tasks = _load("bfcl")
    appended = synthesize(tasks, seed=0)
    matched = synthesize(tasks, seed=0, length_matched=True)
    assert 0 < len(matched) < len(appended)
    for v in matched:
        assert v.task.meta.get("length_matched") is True


def test_the_default_is_unchanged():
    """Prior published numbers must stay reproducible rather than shift."""
    tasks = _load("tau2", 100)
    assert synthesize(tasks, seed=0) == synthesize(tasks, seed=0,
                                                   length_matched=False)
