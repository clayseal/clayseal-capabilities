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

#: `clayseal.core.task_scope` lives in the sibling clay-seal-core repository, so
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

    Narrow on purpose. Allow-by-default outside a gate's remit is correct, a
    destination that names no host is nothing for an egress policy to refuse, and
    a huge compute estimate clamped to the ceiling is the rung working. Each gate
    declares its own remit; getting that predicate wrong is how a harness cries
    wolf, which this one did on its first three runs.
    """
    report = run_gate(gate)
    assert not report["NEVER_FAILS_OPEN"], report["NEVER_FAILS_OPEN"]


def test_task_scope_is_total():
    """Was an `xfail` for as long as core was a repository we could not edit.

    `task_scope_allows_path` raised `TypeError`/`AttributeError` on five of the
    twenty adversarial inputs, and the xfail said so along with the reason it was
    not fixed: core was a sibling repo. Core is vendored here now, so the
    exemption expired and the defect was fixed instead. Two of the five needed
    the guard OUTSIDE the `lru_cache`, because the decorator hashes its argument
    before the body runs and an unhashable input never reaches an isinstance
    check.

    The same investigation found that the fix was not enough on its own: a
    differential fuzz against the second path matcher turned up a deny-list
    bypass through backslash separators. See
    `python/tests/test_path_matcher_agreement.py`.
    """
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


# ------------------------------------- a broken component, not a hostile input --
def test_no_broken_component_turns_a_refusal_into_an_allow():
    """The other half of totality, and the half a production incident is made of.

    This file checks that hostile INPUTS never yield a confused allow.
    `stress_faults` checks the case where the input is ordinary and a COMPONENT
    is broken: a ledger times out, a provenance graph raises, an audit sink
    fills up. Four defects were found that way, all of them a component with no
    authority over a decision being able to prevent one.
    """
    from benchmarks.stress_faults import (
        POLICY,
        SEAMS,
        _benign,
        _hostile,
        outcome_with_fault,
        verdict,
    )
    from clayseal.capabilities.policy import load_policy_text

    healthy = load_policy_text(POLICY).build().authorize(_benign()).outcome
    bad = []
    for label, kind, holder, attribute in SEAMS:
        benign = outcome_with_fault(holder, attribute, _benign())
        hostile = outcome_with_fault(holder, attribute, _hostile())
        result = verdict(kind, benign, hostile, healthy)
        if result not in ("ok", "skipped"):
            bad.append(f"{label} ({kind}): benign={benign} hostile={hostile} -> {result}")
    assert not bad, bad


def test_every_seam_is_actually_reachable():
    """Guards the guard. A skipped seam in a table of green ones reads as covered.

    Six of twelve seams were once reported `skipped`: two frozen dataclasses and
    four method names guessed rather than read off the objects.
    """
    from benchmarks.stress_faults import SEAMS, _benign, outcome_with_fault

    unreachable = [
        label for label, _kind, holder, attribute in SEAMS
        if outcome_with_fault(holder, attribute, _benign())
        in ("absent", "unpatchable")
    ]
    assert not unreachable, unreachable
