"""The validity gates, including the three bugs they had on first contact.

A checklist that only ever passes is decoration. These tests assert both
directions for every mechanical gate, and pin the three defects the gates
themselves shipped with, each of which made the audit blame the evaluation for
something the gate had got wrong.
"""
import pytest

from benchmarks.validity import GATES, audit

SYSTEM = "sys"


def _cell(cond, contained, completed, **kw):
    return {"condition": cond, "scenario": kw.pop("scenario", "s1"),
            "contained": contained, "completed": completed, "n": kw.pop("n", 10),
            **kw}


def _good_cells():
    return [
        _cell("allow-all", False, True), _cell("deny-all", True, False),
        _cell("baseline", False, True),
        _cell(SYSTEM, True, True, expected="contain"),
    ]


GOOD_META = {
    "system": SYSTEM, "sampling_frame": "declared", "calibration_split": "held out",
    "operating_point": "fixed a priori", "deployment_shape": "multi-process",
    "attacker_knowledge": ["blind", "oracle"],
    "labels_provenance": "set before measurement",
}


def _by_pitfall(findings):
    return {f.pitfall.split()[0]: f for f in findings}


def test_a_complete_evaluation_passes_every_gate():
    findings = audit(_good_cells(), GOOD_META)
    failed = [str(f) for f in findings if not f.passed]
    assert failed == [], failed


@pytest.mark.parametrize("drop", ["sampling_frame", "calibration_split",
                                  "operating_point", "deployment_shape",
                                  "labels_provenance"])
def test_a_missing_declaration_is_a_finding(drop):
    """An unanswered question is a finding, not a pass."""
    meta = {k: v for k, v in GOOD_META.items() if k != drop}
    assert any(not f.passed for f in audit(_good_cells(), meta))


def test_missing_trivial_controls_blocks():
    cells = [c for c in _good_cells() if c["condition"] != "deny-all"]
    assert not _by_pitfall(audit(cells, GOOD_META))["P4"].passed


def test_a_single_column_result_blocks():
    """P7, the one that matters most: a security column alone is winnable by
    refusing everything."""
    cells = _good_cells()
    cells[-1].pop("completed")
    assert not _by_pitfall(audit(cells, GOOD_META))["P7"].passed


def test_losing_to_a_baseline_on_the_joint_score_blocks():
    cells = _good_cells() + [_cell("baseline", True, True, scenario="s2"),
                             _cell(SYSTEM, False, True, scenario="s2",
                                   expected="contain")]
    assert not _by_pitfall(audit(cells, GOOD_META))["P6"].passed


def test_one_knowledge_level_blocks():
    meta = dict(GOOD_META, attacker_knowledge=["blind"])
    assert not _by_pitfall(audit(_good_cells(), meta))["P10"].passed


# --------------------------------------------------------------------------- #
# The gates' own bugs, pinned
# --------------------------------------------------------------------------- #
def test_partial_labels_cannot_disagree():
    """Bug 1: `partial` makes no checkable claim.

    Counting it as a mismatch made the audit report 36% label disagreement on a
    corpus whose real contradiction rate is 25%.
    """
    cells = _good_cells() + [
        _cell(SYSTEM, False, True, scenario=f"p{i}", expected="partial")
        for i in range(20)]
    assert _by_pitfall(audit(cells, GOOD_META))["P2"].passed


def test_labels_are_checked_only_against_the_system_under_test():
    """Bug 2: a corpus label describes the system, not every condition.

    Checking it against the baselines too trebled the apparent disagreement
    the baselines are SUPPOSED to fail a scenario labelled `contain`.
    """
    cells = _good_cells() + [
        _cell("baseline", False, True, scenario=f"b{i}", expected="contain")
        for i in range(30)]
    assert _by_pitfall(audit(cells, GOOD_META))["P2"].passed


def test_a_deterministic_replay_may_have_n_of_one():
    """Bug 3: a scripted replay has no sampling error.

    Demanding n>=5 of it confused 'few samples' with 'no randomness'. The
    declaration is required, so an evaluation cannot claim it silently.
    """
    cells = [dict(c, n=1) for c in _good_cells()]
    assert not _by_pitfall(audit(cells, GOOD_META))["P8"].passed
    assert _by_pitfall(audit(cells, dict(GOOD_META, deterministic=True)))["P8"].passed


def test_control_aliases_are_accepted():
    """A gate that fails on vocabulary rather than substance gets muted."""
    cells = [_cell("none", False, True), _cell("deny-all", True, False),
             _cell("baseline", False, True),
             _cell(SYSTEM, True, True, expected="contain")]
    meta = dict(GOOD_META, control_aliases={"none": "allow-all"})
    assert _by_pitfall(audit(cells, meta))["P4"].passed


def test_a_passing_declaration_gate_is_still_reported_as_one():
    """Otherwise a reader cannot tell which verdicts a program actually settled."""
    findings = audit(_good_cells(), GOOD_META)
    assert _by_pitfall(findings)["P1"].kind == "declaration"
    assert _by_pitfall(findings)["P7"].kind == "mechanical"


def test_every_gate_cites_a_defect_it_caught():
    """A gate with no scalp is a guess.

    The taxonomy is Arp et al.'s; the justification for each gate being
    executable rather than prose is that it has already caught something real.
    """
    for gate in GATES:
        assert gate.scalp.strip(), gate.pitfall


def test_label_agreement_requires_provenance():
    """Agreement a project manufactured is not evidence.

    A label re-derived from the run it is compared against is a regression
    guard, not a prediction, and a gate that cannot tell those apart is one a
    project satisfies by editing its own answer key.
    """
    meta = {k: v for k, v in GOOD_META.items() if k != "labels_provenance"}
    finding = _by_pitfall(audit(_good_cells(), meta))["P2"]
    assert not finding.passed
    assert "provenance" in finding.detail
