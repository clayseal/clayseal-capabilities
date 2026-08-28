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
RESULTS = ROOT / "benchmarks" / "results"


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
    readme = _rows(README.read_text(), "harm is defined by", CORPORA)
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
        # README:  corpus | contained | n | harm-defined-by
        # source:  corpus | contained | split | n | what
        assert _pct(readme[c][1]) == _pct(source[c][1]), f"{c} contained"
        assert _plain(readme[c][2]) == _plain(source[c][3]), f"{c} n"


def test_the_saturated_corpora_are_named_and_excluded() -> None:
    """ASB and InjecAgent score 100% and must not be counted as evidence."""
    text = README.read_text()
    assert "excluded from that table rather than counted" in text
    for name in ("ASB", "InjecAgent"):
        assert name in text, f"{name} must be disclosed, not silently dropped"
    for c in ("asb", "injecagent"):
        assert f"| {c} |" not in text, f"{c} must not appear as a scored row"


# --- pooled live ASR --------------------------------------------------------

SUITES = ("banking", "slack", "travel", "workspace")


@pytest.fixture(scope="module")
def pooled():
    readme = _rows(README.read_text(), "defended ASR", SUITES)
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
    readme, _ = _rows(README.read_text(), "defended ASR", SUITES), None
    total = sum(int(_plain(readme[s][3]).split("/")[1]) for s in SUITES)
    assert total == 216, f"rows sum to {total}, README claims 216"
    assert "1 attack success in 216 runs" in README.read_text()


# --- the paired utility 4x4 -------------------------------------------------

MODELS = ("gpt-4o-mini", "gpt-oss-120b", "grok-4-1-fast", "llama-4-maverick")


@pytest.fixture(scope="module")
def utility():
    readme = _rows(README.read_text(), "with Clay Seal", MODELS)
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
