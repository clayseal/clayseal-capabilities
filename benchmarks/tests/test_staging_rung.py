"""The staging rung: what it closes, and what has not been measured about it."""
from __future__ import annotations

import pytest

from agentauth.capabilities.hardening.object_class import ObjectClass, classify
from benchmarks.adaptive import calibrate
from benchmarks.adversarial.adaptive import (
    Knowledge, in_scope_exfiltration_objective, run_adaptive)
from benchmarks.core.engines import LADDER, build_engines
from benchmarks.core.events import EventLabel
from benchmarks.core.runner import run_benchmark
from benchmarks.datasets.base import get_loader

BASE = "task-scope+binding+budget+velocity+density"
STAGING = BASE + "+staging"


def _tasks(name="redcode", limit=60):
    try:
        return list(get_loader(name).load())[:limit]
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"{name}: {exc}")


# --------------------------------------------------------------------------- #
# The taxonomy.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", [
    "/app/.env", "app/.npmrc", "/repo/.git/config", "~/.ssh/id_rsa",
    "/app/config/secrets.yaml", "/svc/service-account.json", "/a/API_KEY.txt",
])
def test_secret_classed_objects_are_recognised(path):
    assert classify(path) is ObjectClass.SECRET


@pytest.mark.parametrize("path", [
    "/app/README.md", "app/docs/guide.md", "/app/public/index.html",
    "/app/dist/bundle.js", "/site/CHANGELOG",
])
def test_publication_classed_objects_are_recognised(path):
    assert classify(path) is ObjectClass.PUBLICATION


def test_secret_wins_when_an_object_matches_both():
    """`docs/secrets.md` is both. Reading it as a publication surface is the
    dangerous direction, so the ordering is the conservative one."""
    assert classify("/app/docs/secrets.md") is ObjectClass.SECRET


@pytest.mark.parametrize("junk", [None, "", "   ", 0, [1], {"a": 1}, True])
def test_classify_is_total(junk):
    assert classify(junk) is ObjectClass.ORDINARY


# --------------------------------------------------------------------------- #
# What it closes.
# --------------------------------------------------------------------------- #
def test_the_staging_rung_contains_what_the_ladder_below_it_cannot():
    """Before: the full ladder's escaped set was byte-identical to allow-all."""
    tasks = _tasks()
    objective = in_scope_exfiltration_objective()
    engines = calibrate(build_engines([BASE, STAGING]), tasks, seed=0)
    escaped = {}
    for engine in engines:
        result = run_adaptive(tasks, engine, objective=objective,
                              knowledge=Knowledge.ORACLE, rounds=3, seed=0,
                              breadth=6)
        escaped[engine.name] = {e.task_id for e in result.escapes}
    assert escaped[BASE], "premise stale: the base ladder now contains this"
    assert not escaped[STAGING], escaped[STAGING]


def test_it_adds_no_false_blocks_on_the_corpora_we_have():
    """True, and see the next test for why it is not the reassurance it looks."""
    for name in ("redcode", "tau2", "atif"):
        tasks = _tasks(name, limit=400)
        res = run_benchmark(tasks, build_engines([BASE, STAGING]),
                            calibration_seed=0)
        assert res[STAGING].false_block_rate == res[BASE].false_block_rate, name


def test_the_friction_of_this_rung_is_unmeasured_not_zero():
    """The honest reading of the row above.

    The rung fires only on the CONJUNCTION of a secret-classed read and a
    publication-classed write in one session. Across 20,299 benign events in
    seven corpora that conjunction occurs in **zero** tasks, so its false-block
    rate is untested rather than low. A real coding agent reads `.env` for
    configuration and later edits a README constantly.

    Asserted so the absence is a fact in CI rather than a footnote: if a corpus
    ever does exercise it, this fails and the friction number becomes real and
    has to be looked at.
    """
    triggered = 0
    for name in ("redcode", "tau2", "bfcl", "atif", "toolemu", "agentharm"):
        for task in _tasks(name, limit=4000):
            saw_secret = saw_pub = False
            for event in task.events:
                if event.label is not EventLabel.BENIGN:
                    continue
                kind = classify(event.path or event.resource or "")
                verb = (event.action or "").lower()
                read = verb in {"read", "get", "list", "search", "query"}
                if kind is ObjectClass.SECRET and read:
                    saw_secret = True
                if kind is ObjectClass.PUBLICATION and not read:
                    saw_pub = True
            triggered += saw_secret and saw_pub
    assert triggered == 0, (
        f"{triggered} benign tasks now exercise the staging rung — its "
        "false-block rate is measurable, so measure it before shipping DENY")


def test_the_rung_is_not_in_the_shipped_ladder():
    """Out until the friction is measured on real sessions, and until the
    deployment posture is STEP_UP rather than DENY."""
    assert STAGING not in LADDER
