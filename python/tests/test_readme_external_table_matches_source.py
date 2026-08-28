"""The README's AgentDojo table must agree with the result file it came from.

The README restates four rows of `benchmarks/results/head_to_head_injection.md`.
A number restated in a second place drifts, and this repository has already been
bitten by exactly that: four documents once quoted four different p50s for "the
full stack". This pins the copy to the original so the copy cannot go stale
quietly.

The "best AgentDojo built-in" column is derived rather than copied, so it is
recomputed here from the three built-in columns instead of being trusted.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"
SOURCE = ROOT / "benchmarks" / "results" / "head_to_head_injection.md"

SUITES = ("banking", "slack", "travel", "workspace")


def _pct(cell: str) -> float:
    m = re.search(r"(\d+(?:\.\d+)?)%", cell)
    assert m, f"no percentage in cell {cell!r}"
    return float(m.group(1))


def _rows(text: str, header_probe: str) -> dict[str, list[str]]:
    """Return {suite: [cells]} for the first table whose header contains a probe."""
    out: dict[str, list[str]] = {}
    in_table = False
    for line in text.splitlines():
        if not line.startswith("|"):
            if in_table and out:
                break
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if header_probe in line:
            in_table = True
            continue
        if not in_table or set(line) <= set("|-: "):
            continue
        if cells and cells[0] in SUITES:
            out[cells[0]] = cells
    return out


@pytest.fixture(scope="module")
def tables() -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    readme = _rows(README.read_text(), "best AgentDojo built-in")
    source = _rows(SOURCE.read_text(), "tool_filter")
    return readme, source


def test_both_tables_were_actually_found(tables) -> None:
    """Control: if either parse silently returns nothing, every other test passes."""
    readme, source = tables
    assert set(readme) == set(SUITES), f"README table not parsed: {sorted(readme)}"
    assert set(source) == set(SUITES), f"source table not parsed: {sorted(source)}"


def test_undefended_progent_and_ours_match_the_source(tables) -> None:
    readme, source = tables
    for suite in SUITES:
        # README:  suite | undefended | best built-in | Progent | ours
        # source:  suite | undefended | tool_filter | spotlighting | repeat_prompt | Progent | ours
        assert _pct(readme[suite][1]) == _pct(source[suite][1]), f"{suite} undefended"
        assert _pct(readme[suite][3]) == _pct(source[suite][5]), f"{suite} Progent"
        assert _pct(readme[suite][4]) == _pct(source[suite][6]), f"{suite} ours"


def test_best_builtin_column_is_the_best_builtin(tables) -> None:
    readme, source = tables
    for suite in SUITES:
        builtins = [_pct(source[suite][i]) for i in (2, 3, 4)]
        assert _pct(readme[suite][2]) == min(builtins), (
            f"{suite}: README claims {readme[suite][2]} is the best built-in, "
            f"but the source columns are {builtins}"
        )


def test_the_comparison_would_notice_a_wrong_number(tables) -> None:
    """Control: the checks above fail when a copied number is perturbed."""
    readme, source = tables
    bad = {s: list(cells) for s, cells in readme.items()}
    bad["banking"][3] = "99.9%"
    assert _pct(bad["banking"][3]) != _pct(source["banking"][5])


# --- the utility 4x4, pinned to live_ladder.md -----------------------------

LADDER = ROOT / "benchmarks" / "results" / "live_ladder.md"
MODELS = ("gpt-4o-mini", "gpt-oss-120b", "grok-4-1-fast", "llama-4-maverick")


def _model_rows(text: str, header_probe: str) -> dict[str, list[str]]:
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
        if name in MODELS:
            out[name] = cells
    return out


@pytest.fixture(scope="module")
def utility_tables() -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    readme = _model_rows(README.read_text(), "with Clay Seal")
    ladder = _model_rows(LADDER.read_text(), "endorse/task")
    return readme, ladder


def test_both_utility_tables_were_found(utility_tables) -> None:
    """Control: an empty parse would make every assertion below vacuous."""
    readme, ladder = utility_tables
    assert set(readme) == set(MODELS), f"README 4x4 not parsed: {sorted(readme)}"
    assert set(ladder) == set(MODELS), f"ladder 4x4 not parsed: {sorted(ladder)}"


def test_readme_utility_numbers_match_the_ladder(utility_tables) -> None:
    readme, ladder = utility_tables
    for m in MODELS:
        # README: model | undefended | with Clay Seal | cost | false-block
        # ladder: Model | baseline | envelope | taint | oracle | cost | fb | endorse
        assert _pct(readme[m][1]) == _pct(ladder[m][1]), f"{m} baseline"
        assert _pct(readme[m][2]) == _pct(ladder[m][2]), f"{m} envelope utility"
        assert _pct(readme[m][4]) == _pct(ladder[m][6]), f"{m} false-block"


def test_the_quoted_cost_is_the_measured_difference(utility_tables) -> None:
    """The cost column must be baseline minus defended, not an independent number.

    Tolerance is one point, and it is not slack. Both percentages are rounded to
    whole numbers over 32 tasks, so their printed difference can sit up to a
    point away from the difference of the underlying fractions. gpt-oss-120b is
    the live case: 27/32 and 21/32 differ by 18.75, printed as 84 and 66, whose
    difference reads as 18 and whose true cost rounds to 19. A tolerance of zero
    fails a correct table; anything above one stops catching a wrong one.
    """
    readme, _ = utility_tables
    for m in MODELS:
        stated = re.search(r"(-|−)?\s*(\d+)\s*pts", readme[m][3])
        assert stated, f"{m}: no 'pts' figure in {readme[m][3]!r}"
        magnitude = int(stated.group(2))
        derived = _pct(readme[m][1]) - _pct(readme[m][2])
        assert abs(magnitude - derived) <= 1.0, (
            f"{m}: README states {magnitude} pts but "
            f"{readme[m][1]} - {readme[m][2]} is {derived}"
        )
