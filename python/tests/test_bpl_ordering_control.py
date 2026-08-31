"""The BPL suite must not be scorable by call position alone.

`ordering_exposure.py` found four event corpora whose 100% containment a pure
position cut also reaches, which makes their number evidence about the corpus
rather than about the mechanism. BPL carries the headline and had never been
checked. These tests pin the control's own correctness, because a broken control
reports the most flattering possible result.
"""

from __future__ import annotations

import pytest

from benchmarks.bpl_ordering_control import run


@pytest.fixture(scope="module")
def out():
    return run("full", max_k=60)


def test_the_controls_endpoints_are_the_two_degenerate_policies(out) -> None:
    """k=0 must be deny-all and k=max must be allow-all.

    Both were wrong at first. The sweep's top end truncated the four longest
    scripts, so the "block nothing" endpoint still refused calls and reported 102
    completions where allow-all reaches 132. A control whose null endpoint is
    wrong cannot bound anything.
    """
    pos = [r for r in out["rows"] if r["rule"] == "position cut"]
    assert (pos[0]["contained"], pos[0]["completed"]) == (out["n"], 0)
    assert (pos[-1]["contained"], pos[-1]["completed"]) == (0, out["n"])


def test_counting_is_graded_on_the_same_metric_as_the_gateway(out) -> None:
    """`completed` is "nothing refused", not `progress >= 1.0`.

    Thirty compliant scripts end below 1.0 with nothing blocked at all, so an
    extra progress clause holds the control to a STRICTER standard than the
    gateway it checks and understates it. That error runs in our favour, which
    is the kind nobody goes looking for.
    """
    pos = [r for r in out["rows"] if r["rule"] == "position cut"]
    assert pos[-1]["completed"] == out["n"], (
        "with nothing blocked every twin must count as completed"
    )


def test_the_suite_is_not_ordering_exposed(out) -> None:
    """At the gateway's friction budget, counting must not be competitive."""
    matched = [r for r in out["rows"] if r["completed"] >= 130]
    best = max((r["contained"] for r in matched), default=0)
    assert best < 10, (
        f"a position cut contains {best} at the gateway's own friction budget; "
        "the suite would be reporting the shape of its scripts"
    )


def test_the_best_joint_a_counting_rule_reaches_is_far_below_the_gateway(out) -> None:
    best = max(r["joint"] for r in out["rows"])
    assert best < 10, f"counting reaches joint {best}; the gateway reaches 70"
