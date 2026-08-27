"""The claims linter, and the limits it admits to."""
from __future__ import annotations

from pathlib import Path

from benchmarks.check_claims import main, scan, status_of


def test_it_passes_on_the_current_tree():
    """The ratchet is at its baseline, so CI is green until somebody adds debt."""
    assert main([]) == 0


def test_a_bare_zero_is_recognised(tmp_path: Path):
    f = tmp_path / "r.md"
    f.write_text("# t\n\n| ours | 0.0% |\n")
    assert scan(f)["bare_zero"]


def test_a_zero_with_a_denominator_is_accepted(tmp_path: Path):
    """`0.00% (0 of 1,242)` lets the reader compute the bound. The sin is an
    uncontextualised zero, not the absence of a specific statistic."""
    f = tmp_path / "r.md"
    f.write_text("# t\n\n| ours | 0.00% (0 of 1,242) |\n")
    assert not scan(f)["bare_zero"]


def test_a_zero_with_an_upper_bound_is_accepted(tmp_path: Path):
    f = tmp_path / "r.md"
    f.write_text("# t\n\n0/20, 97.5% upper bound 16.8%\n")
    assert not scan(f)["bare_zero"]


def test_ordinary_percentages_are_not_flagged(tmp_path: Path):
    f = tmp_path / "r.md"
    f.write_text("# t\n\n| a | 10% | 0.05% | 100% |\n")
    assert not scan(f)["bare_zero"]


def test_an_unqualified_forbidden_claim_is_flagged(tmp_path: Path):
    f = tmp_path / "r.md"
    f.write_text("# t\n\nsupervised utility was 84%\n")
    assert scan(f)["forbidden"]


def test_a_file_that_qualifies_in_its_header_complies(tmp_path: Path):
    """File-level, not per line. The caveat is written once at the top and the
    term then appears throughout the body, which is how a caveat is written."""
    f = tmp_path / "r.md"
    f.write_text("# t\n\nEvery supervised utility figure here is a counterfactual.\n"
                 "\nsupervised utility was 84%\nsupervised utility was 79%\n")
    assert not scan(f)["forbidden"]


def test_status_headers_parse(tmp_path: Path):
    for value in ("current", "superseded", "retracted"):
        f = tmp_path / f"{value}.md"
        f.write_text(f"# t\n\nSTATUS: {value}\n\nbody\n")
        assert status_of(f.read_text()) == value


def test_files_i_authored_this_session_are_enforced():
    """Holding my own output to the rule first."""
    results = Path(__file__).parent.parent / "results"
    for name in ("opeval.md", "adequacy.md", "flow_window.md", "staging_rung.md"):
        assert status_of((results / name).read_text()) == "current", name
