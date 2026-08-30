"""Every external number the README restates must match the file it came from.

The README quotes four tables that live elsewhere: the multi-corpus scoreboard,
the pooled AgentDojo ASR, and the paired utility 4x4. A number restated in a
second place drifts, and this repository has been bitten by exactly that twice:
four documents once quoted four different p50s for "the full stack", and
`scoreboard.md` sat stamped `unverified` carrying ladder figures in the product
column while the README quoted them as the product.

What this does NOT do: re-derive anything. It pins a copy to its source
document, so it catches the two documents disagreeing, not both being wrong
together. Re-derivation is `python -m benchmarks.scoreboard` and the ratchet in
`benchmarks/check_claims.py`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"
EVIDENCE = ROOT / "docs" / "EVIDENCE.md"
RESULTS = ROOT / "benchmarks" / "results"

#: Every front-door document that may quote a measured table. Checked as one
#: corpus rather than by name, so moving a table between them is a refactor and
#: not a hole: the pin follows the table instead of the filename. A table that
#: appears in neither still fails, which is the point.
FRONT_DOOR = (README, EVIDENCE)


def _front_door_text() -> str:
    return "\n\n".join(p.read_text() for p in FRONT_DOOR if p.exists())


def _plain(cell: str) -> str:
    """Strip markdown emphasis and spacing so two spellings of a cell compare."""
    return cell.replace("*", "").replace("`", "").replace(" ", "").strip()


def _pct(cell: str) -> float:
    m = re.search(r"(\d+(?:\.\d+)?)\s*%", cell)
    assert m, f"no percentage in cell {cell!r}"
    return float(m.group(1))


def _rows(text: str, header_probe: str, keys: tuple[str, ...]) -> dict[str, list[str]]:
    """Return {key: cells} for the first markdown table whose header matches."""
    out: dict[str, list[str]] = {}
    in_table = False
    for line in text.splitlines():
        if not line.startswith("|"):
            if in_table and out:
                break
            continue
        if header_probe in line:
            in_table = True
            continue
        if not in_table or set(line) <= set("|-: "):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        name = cells[0].strip("* `")
        if name in keys:
            out[name] = cells
    return out


# --- the multi-corpus scoreboard -------------------------------------------

CORPORA = ("redcode", "ipi_coding", "mcp_attack", "agent_threat_bench",
           "advbench_agent", "mind2web_sc", "b3", "agentharm", "sleight")


@pytest.fixture(scope="module")
def scoreboard():
    readme = _rows(_front_door_text(), "harm is defined by", CORPORA)
    source = _rows((RESULTS / "scoreboard.md").read_text(),
                   "what the corpus tests", CORPORA)
    return readme, source


def test_scoreboard_tables_were_found(scoreboard) -> None:
    """Control: an empty parse makes every assertion below vacuous."""
    readme, source = scoreboard
    assert set(readme) == set(CORPORA), f"README: {sorted(readme)}"
    assert set(source) == set(CORPORA), f"scoreboard.md: {sorted(source)}"


def test_scoreboard_containment_and_n_match(scoreboard) -> None:
    readme, source = scoreboard
    for c in CORPORA:
        # README:  corpus | contained | FB complete | FB half | n | harm-defined-by
        # source:  corpus | contained | split | FB complete | FB half | n | what
        assert _pct(readme[c][1]) == _pct(source[c][1]), f"{c} contained"
        assert _plain(readme[c][4]) == _plain(source[c][5]), f"{c} n"


def test_both_friction_columns_are_quoted_and_match(scoreboard) -> None:
    """Containment without a friction column is the number this repo forbids.

    `benchmarks/scoreboard.py` says in its own legend that `FB(granted)` is
    "0.00% by construction" on six of these corpora and "is not evidence on its
    own". The README quoted containment from this table for several releases and
    carried no friction column at all, which is the exact thing the fixed-FPR
    section two screens further down says a headline may not do.

    Both columns are pinned, so dropping either from the README fails here.
    """
    readme, source = scoreboard
    for c in CORPORA:
        assert _plain(readme[c][2]) == _plain(source[c][3]), f"{c} complete-grant"
        assert _plain(readme[c][3]) == _plain(source[c][4]), f"{c} half-grant"


def test_the_held_out_column_is_not_silently_zero(scoreboard) -> None:
    """`not run` must stay `not run`.

    An unmeasured cell rendered as 0.00% reads as "this costs nothing", which is
    the strongest claim in the table and the one nobody measured. The corpora
    where it IS measured have to keep showing a real double-digit number, or the
    column has stopped carrying its point.
    """
    readme, _ = scoreboard
    measured = [c for c in CORPORA if "notrun" not in _plain(readme[c][3])]
    assert measured, "no corpus reports a held-out figure any more"
    for c in measured:
        assert _pct(readme[c][3]) > 10.0, (
            f"{c} half-grant friction is {readme[c][3]}, which would make the "
            f"column decorative")


def test_the_saturated_corpora_are_named_and_excluded() -> None:
    """ASB and InjecAgent must not be counted as containment evidence.

    Scoped to the containment table specifically. Their *benign* sides are
    legitimate evidence and appear in the held-out false-block table, so a
    whole-file substring check would forbid a correct use of them.
    """
    text = _front_door_text()
    # The disclosure has to be there; its exact wording does not. Pinning the
    # sentence made a copy-edit look like a removed disclosure, which is a test
    # that fires on prose and stays quiet on the thing it guards.
    assert ("2,040" in text and "1,598" in text), (
        "the saturated corpora must be disclosed with their sizes")
    for name in ("ASB", "InjecAgent"):
        assert name in text, f"{name} must be disclosed, not silently dropped"
    scored = _rows(text, "harm is defined by", CORPORA + ("asb", "injecagent"))
    for c in ("asb", "injecagent"):
        assert c not in scored, f"{c} must not appear as a scored containment row"


# --- pooled live ASR --------------------------------------------------------

SUITES = ("banking", "slack", "travel", "workspace")


@pytest.fixture(scope="module")
def pooled():
    readme = _rows(_front_door_text(), "defended ASR", SUITES)
    source = _rows((RESULTS / "pooled_asr.md").read_text(), "sweep spread", SUITES)
    return readme, source


def test_pooled_tables_were_found(pooled) -> None:
    """Control."""
    readme, source = pooled
    assert set(readme) == set(SUITES), f"README: {sorted(readme)}"
    assert set(source) == set(SUITES), f"pooled_asr.md: {sorted(source)}"


def test_pooled_asr_matches(pooled) -> None:
    readme, source = pooled
    for s in SUITES:
        assert _pct(readme[s][1]) == _pct(source[s][1]), f"{s} undefended"
        assert _pct(readme[s][2]) == _pct(source[s][2]), f"{s} defended"
        assert _plain(readme[s][3]) == _plain(source[s][3]), f"{s} runs"


def test_the_pooled_denominator_is_216() -> None:
    """The headline says 216 runs; the rows must add up to it."""
    readme, _ = _rows(_front_door_text(), "defended ASR", SUITES), None
    total = sum(int(_plain(readme[s][3]).split("/")[1]) for s in SUITES)
    assert total == 216, f"rows sum to {total}, the tables claim 216"
    assert "1 attack success in 216 runs" in _front_door_text()


# --- the paired utility 4x4 -------------------------------------------------

MODELS = ("gpt-4o-mini", "gpt-oss-120b", "grok-4-1-fast", "llama-4-maverick")


@pytest.fixture(scope="module")
def utility():
    readme = _rows(_front_door_text(), "with Clay Seal", MODELS)
    ladder = _rows((RESULTS / "live_ladder.md").read_text(), "endorse/task", MODELS)
    return readme, ladder


def test_utility_tables_were_found(utility) -> None:
    """Control."""
    readme, ladder = utility
    assert set(readme) == set(MODELS), f"README: {sorted(readme)}"
    assert set(ladder) == set(MODELS), f"live_ladder.md: {sorted(ladder)}"


def test_utility_numbers_match_the_ladder(utility) -> None:
    readme, ladder = utility
    for m in MODELS:
        # README: model | undefended | with Clay Seal | cost | false-block
        # ladder: Model | baseline | envelope | taint | oracle | cost | fb | endorse
        assert _pct(readme[m][1]) == _pct(ladder[m][1]), f"{m} baseline"
        assert _pct(readme[m][2]) == _pct(ladder[m][2]), f"{m} defended"
        assert _pct(readme[m][4]) == _pct(ladder[m][6]), f"{m} false-block"


def test_the_quoted_cost_is_the_measured_difference(utility) -> None:
    """The cost column must be baseline minus defended, not a free-standing number.

    Tolerance is one point, and it is not slack. Both percentages are rounded to
    whole numbers over 32 tasks, so their printed difference can sit up to a
    point from the difference of the underlying fractions. gpt-oss-120b is the
    live case: 27/32 and 21/32 differ by 18.75, printed as 84 and 66, whose
    difference reads as 18 while the true cost rounds to 19. Zero tolerance
    fails a correct table; more than one stops catching a wrong one.
    """
    readme, _ = utility
    for m in MODELS:
        stated = re.search(r"(-|−)?\s*(\d+)\s*pts", readme[m][3])
        assert stated, f"{m}: no 'pts' figure in {readme[m][3]!r}"
        derived = _pct(readme[m][1]) - _pct(readme[m][2])
        assert abs(int(stated.group(2)) - derived) <= 1.0, (
            f"{m}: README states {stated.group(2)} pts but "
            f"{readme[m][1]} - {readme[m][2]} is {derived}"
        )
