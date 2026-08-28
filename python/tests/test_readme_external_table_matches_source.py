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
