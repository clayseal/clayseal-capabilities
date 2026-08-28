"""A zero in a table whose `n` is stated above it is not a bare zero.

The rule is about an UNCONTEXTUALISED zero. It was reading every cell of every
results table as one, because the denominator of a table is written once, in the
caption or the header, and then a grid of rates follows:

    ## Banking, gpt-4o-mini, envelope_aware attack, n=18

    | configuration | clean utility | ASR | utility under attack |
    |---|--:|--:|--:|
    | full stack | 50.0% | **0.0%** | 27.8% |

That `0.0%` is `0 of 18` and a reader can compute its bound. Counting it as debt
put findings on the ratchet that were not the sin the rule describes, and a debt
counter that mostly counts false positives is one nobody acts on — which hides
the ones that are real.

The danger in relaxing a linter is relaxing it too far, and the first version of
this did: it accepted `HAS_BOUND`, which matches `n/a`, and it read across a
blank line into the PREVIOUS table, so a row of an unrelated table four lines up
vouched for this one. Both halves are tested below, because a check weakened by a
spurious match is exactly what `check_claims.py` exists to catch.
"""
from __future__ import annotations

import pathlib
import tempfile

import pytest

from benchmarks.check_claims import scan


def _scan_text(text: str):
    path = pathlib.Path(tempfile.mkstemp(suffix=".md")[1])
    try:
        path.write_text(text)
        return scan(path)["bare_zero"]
    finally:
        path.unlink()


CAPTIONED_TABLE = """# probe

## Banking, gpt-4o-mini, n=18

| configuration | ASR |
|---|--:|
| full stack | 0.0% |
"""

HEADER_TABLE = """# probe

| arm | contained (of 200) |
|---|--:|
| taint | 0.0% |
"""

NAKED_TABLE = """# probe

## Results

| arm | rate |
|---|--:|
| taint | 0.0% |
"""

ACROSS_A_PREVIOUS_TABLE = """# probe

| other table | value |
|---|---|
| something | n/a |

### A different section

| arm | rate |
|---|--:|
| taint | 0.0% |
"""

UNBOUNDED_PROSE = "# probe\n\nThe detector reached 0.0% false blocks.\n"
BOUNDED_PROSE = "# probe\n\nThe detector reached 0.0% false blocks (0 of 1,242).\n"


def test_a_table_whose_caption_states_n_is_contextualised():
    assert not _scan_text(CAPTIONED_TABLE)


def test_a_table_whose_header_states_the_denominator_is_contextualised():
    assert not _scan_text(HEADER_TABLE)


def test_a_table_that_states_no_denominator_is_still_flagged():
    """The relaxation must not swallow the case the rule is for."""
    assert _scan_text(NAKED_TABLE)


def test_a_previous_table_cannot_vouch_for_this_one():
    """The bug in the first version of this rule.

    `n/a` in a row of an unrelated table, four lines up across a blank line and a
    heading, exempted a whole table. `n/a` means the rate does not apply; it is
    not a sample size.
    """
    assert _scan_text(ACROSS_A_PREVIOUS_TABLE)


def test_prose_is_unaffected_in_both_directions():
    """The table rule must not leak into ordinary sentences."""
    assert _scan_text(UNBOUNDED_PROSE)
    assert not _scan_text(BOUNDED_PROSE)


@pytest.mark.parametrize("denominator", ["n=18", "0 of 1,242", "12/200",
                                         "97.5% upper bound"])
def test_the_forms_a_caption_actually_uses_all_count(denominator):
    assert not _scan_text(
        f"# probe\n\nMeasured over {denominator}.\n\n"
        "| arm | rate |\n|---|--:|\n| taint | 0.0% |\n")


@pytest.mark.parametrize("not_a_denominator", ["n/a", "±", "interval"])
def test_a_qualifier_is_not_a_sample_size(not_a_denominator):
    """`HAS_BOUND` accepts these on the same line as a rate, where they qualify
    that rate. None of them tells a reader how many trials a table ran."""
    assert _scan_text(
        f"# probe\n\nSomething {not_a_denominator} here.\n\n"
        "| arm | rate |\n|---|--:|\n| taint | 0.0% |\n")


def test_the_scanner_is_not_simply_off():
    """The control.

    Every "is flagged" assertion above fails if the scanner stopped running, but
    every "is not flagged" one would pass. Assert the scanner still finds the
    plainest possible violation.
    """
    found = _scan_text(UNBOUNDED_PROSE)
    assert found and found[0][0] == 3, found
