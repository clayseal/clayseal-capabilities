"""A crash must not be able to pass for containment.

`StackEngine.decide` scores an exception as "not allowed" so that one broken
task cannot take down a sweep. That means a crash counts as a contained attack.
If a change starts throwing on the attacks it can no longer decide, containment
would RISE and nothing in the published tables would say why.
"""
from __future__ import annotations

import pytest

CORPORA = ["agentharm", "sleight", "redcode", "asb", "injecagent", "agentleak"]


@pytest.mark.parametrize("corpus", CORPORA)
def test_no_decision_in_the_corpus_ends_in_an_exception(corpus):
    from benchmarks.core.stack_engine import DeployableStackEngine
    from benchmarks.datasets.base import get_loader

    try:
        tasks = get_loader(corpus).load(limit=4000)
    except Exception as exc:  # noqa: BLE001 - corpus not fetched in this checkout
        pytest.skip(f"{corpus} unavailable: {str(exc)[:60]}")
    if not tasks:
        pytest.skip(f"{corpus} loaded no tasks")

    engine = DeployableStackEngine(name="errors", treat_step_up="block")
    for task in tasks:
        engine.reset()
        for event in task.events:
            engine.decide(task, event)

    assert engine.stack_errors == 0, (
        f"{engine.stack_errors} decisions on {corpus} ended in an exception and "
        f"were scored as contained: {engine.stack_error_kinds}")
