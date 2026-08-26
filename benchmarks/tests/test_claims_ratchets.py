"""The three ratchets, that they only turn one way, and that they lock.

`check_claims` is advisory by design: it counts debt and fails only when the
count rises. That makes it survivable, and it makes the ratchet itself the
load-bearing part. A ratchet that can be quietly removed, or that never fires, is
a linter that reports a number nobody has to act on.
"""
from __future__ import annotations

import json

import pytest

from benchmarks import check_claims

RESULTS = check_claims.RESULTS


@pytest.fixture
def probe():
    """A results file that is created and removed around one assertion."""
    path = RESULTS / "_ratchet_probe.md"
    yield path
    path.unlink(missing_ok=True)


def _baseline() -> dict:
    return json.loads(check_claims.BASELINE.read_text())


def test_the_tree_is_currently_at_its_baseline():
    """If this fails someone added debt without moving the baseline, or the other
    way round, and both need a person rather than a rerun."""
    assert check_claims.main([]) == 0


def test_the_baseline_records_every_ratchet():
    saved = _baseline()
    for key in ("bare_zero_total", "unverifiable_total", "costless_total"):
        assert key in saved, f"{key} has no baseline, so that ratchet cannot fire"


def test_containment_with_no_cost_column_fails(probe, capsys):
    """`deny-all` contains everything, so containment alone is not a result.

    Three published numbers in this repository turned out to be deny-all wearing
    a reason string, and each was found by running the cost side. This is the
    check that notices the cost side is missing.
    """
    probe.write_text(
        "# Probe\n\n```bash\npython -m benchmarks.burst\n```\n\nSTATUS: current\n\n"
        "| thing | rate |\n| --- | --- |\n| contained | 41/50 |\n")
    assert check_claims.main([]) == 1
    assert "not a measurement" in capsys.readouterr().out


def test_naming_the_cost_is_enough_to_pass(probe):
    """The rule asks whether the question was PUT, not how it was answered."""
    probe.write_text(
        "# Probe\n\n```bash\npython -m benchmarks.burst\n```\n\nSTATUS: current\n\n"
        "| thing | rate |\n| --- | --- |\n| contained | 41/50 |\n"
        "| benign interrupted | 2/50 |\n")
    assert check_claims.main([]) == 0


def test_a_new_result_with_no_command_and_no_status_fails(probe, capsys):
    """The debt this ratchet exists to stop.

    A results file recording neither what produced it nor a status is a number
    nobody can check and nobody has vouched for. 24 of those already exist; the
    ratchet is what stops there being 25.
    """
    probe.write_text("# Probe\n\n| thing | value |\n| --- | --- |\n| x | 5 |\n")
    assert check_claims.main([]) == 1
    assert "only turns one way" in capsys.readouterr().out


def test_the_same_file_passes_once_it_says_what_produced_it(probe):
    probe.write_text(
        "# Probe\n\n```bash\npython -m benchmarks.burst\n```\n\n"
        "| thing | value |\n| --- | --- |\n| x | 5 |\n"
    )
    assert check_claims.main([]) == 0


def test_a_command_declared_inline_also_counts(probe):
    """`flow.md` and `frontier.md` declare theirs in backticks rather than a
    fenced block. Only the fencing differs, and a checker that reads one and not
    the other invents a distinction the authors never made."""
    probe.write_text(
        "# Probe\n\nProduced by `python -m benchmarks.burst`.\n\n"
        "| thing | value |\n| --- | --- |\n| x | 5 |\n"
    )
    assert check_claims.main([]) == 0


def test_a_bare_zero_in_a_new_file_fails(probe, capsys):
    probe.write_text(
        "# Probe\n\n```bash\npython -m benchmarks.burst\n```\n\n"
        "| thing | rate |\n| --- | --- |\n| contained | 0% |\n"
    )
    assert check_claims.main([]) == 1
    assert "bare-zero" in capsys.readouterr().out


def test_a_zero_with_its_bound_passes(probe):
    """The rule is against an UNCONTEXTUALISED zero, not against the digit."""
    from benchmarks.core.reporting import format_rate

    # The benign column is here because a file reporting containment without one
    # trips the `costless` ratchet, which is a different rule. Each probe should
    # be well-formed for every rule but the one it is testing.
    probe.write_text(
        "# Probe\n\n```bash\npython -m benchmarks.burst\n```\n\n"
        f"| thing | rate |\n| --- | --- |\n| contained | {format_rate(0, 250)} |\n"
        f"| benign interrupted | {format_rate(3, 250)} |\n"
    )
    assert check_claims.main([]) == 0
