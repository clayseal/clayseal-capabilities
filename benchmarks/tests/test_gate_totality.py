"""Every gate is total: any input yields a decision, never an exception, and
never an allow issued out of confusion.

This is the bug class from `benchmarks/results/budget_fail_open.md` turned into a
standing test. Four defects were found and fixed one at a time; fixing four sites
does not remove a class. Running the same hostile corpus against every gate does,
because the next gate someone adds is audited without anyone remembering to.
"""
from __future__ import annotations

import pytest

from benchmarks.stress_gates import GATES, run_gate

#: `agentauth.core.task_scope` lives in the sibling clay-seal-core repository, so
#: it is reported here rather than patched from this one. See the writeup.
EXTERNAL = {"task-scope"}

IN_REPO = sorted(set(GATES) - EXTERNAL)


@pytest.mark.parametrize("gate", IN_REPO)
def test_a_gate_never_raises_unexpectedly(gate):
    """An authorization gate may deny; it may not throw.

    An exception in the decision path is a denial of service at best, and at
    worst it is swallowed by a broad handler upstream and becomes an allow.
    Typed validation errors a gate documents as its denial mechanism are declared
    in the harness and do not count.
    """
    report = run_gate(gate)
    assert not report["NEVER_RAISES"], report["NEVER_RAISES"]


@pytest.mark.parametrize("gate", IN_REPO)
def test_a_gate_never_allows_out_of_confusion(gate):
    """For an input the gate is supposed to police, an unusable value must not
    be allowed.

    Narrow on purpose. Allow-by-default outside a gate's remit is correct — a
    destination that names no host is nothing for an egress policy to refuse, and
    a huge compute estimate clamped to the ceiling is the rung working. Each gate
    declares its own remit; getting that predicate wrong is how a harness cries
    wolf, which this one did on its first three runs.
    """
    report = run_gate(gate)
    assert not report["NEVER_FAILS_OPEN"], report["NEVER_FAILS_OPEN"]


@pytest.mark.xfail(
    reason="agentauth.core.task_scope_allows_path raises TypeError/AttributeError "
           "on non-string paths. It lives in the sibling clay-seal-core repo, so "
           "it is reported rather than patched from here. broker._action_path "
           "filters with isinstance(v, str), so the shipped gateway is unaffected; "
           "a third-party gateway calling the public API directly is not. "
           "Remove this xfail when core is fixed.",
    strict=True,
)
def test_task_scope_is_total():
    report = run_gate("task-scope")
    assert not report["NEVER_RAISES"], report["NEVER_RAISES"]


def test_the_harness_covers_every_gate_the_broker_composes():
    """A gate absent from the harness is a gate nobody is fuzzing.

    Pinned so that adding a rung to the broker without adding it here is a test
    failure rather than a silent coverage hole.
    """
    expected = {"value-budget", "call-budget", "compute-budget",
                "task-scope", "protected-zones", "egress-policy"}
    assert expected <= set(GATES), sorted(expected - set(GATES))
