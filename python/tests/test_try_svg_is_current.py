"""The README's picture has to be a picture of what the command does now.

A terminal screenshot in a README is the most quietly rotting thing in a
repository. It looks like evidence, nobody re-runs it, and the day the demo
changes it becomes a picture of a program that no longer exists.

`scripts/render_try_svg.py` generates the SVG from a live run, so it cannot be
edited into saying something false. This is the other half: it fails when the
committed picture and the current output have drifted apart, and it says which
command puts them back in sync.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SVG = ROOT / "docs" / "assets" / "clayseal-try.svg"
REGENERATE = "python scripts/render_try_svg.py"


def _svg_text() -> list[str]:
    """The visible characters of the SVG, one entry per drawn line."""
    body = SVG.read_text()
    lines = []
    for element in re.findall(r"<text\b[^>]*>(.*?)</text>", body, re.DOTALL):
        stripped = re.sub(r"<[^>]+>", "", element)
        lines.append(
            stripped.replace("&lt;", "<").replace("&gt;", ">")
                    .replace("&quot;", '"').replace("&amp;", "&"))
    return lines


def test_the_picture_exists_and_is_committed() -> None:
    assert SVG.exists(), f"{SVG} is missing; run: {REGENERATE}"


def test_the_picture_matches_what_the_command_prints() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "clayseal.capabilities.cli", "try", "--fast"],
        cwd=ROOT, capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    printed = [ln.rstrip() for ln in result.stdout.splitlines() if ln.strip()]
    drawn = [ln.rstrip() for ln in _svg_text() if ln.strip()]
    # The window chrome adds a title the program never printed.
    drawn = [ln for ln in drawn if ln != "clayseal try"]

    missing = [ln for ln in printed if ln.strip() not in {d.strip() for d in drawn}]
    assert not missing, (
        f"{len(missing)} line(s) the command prints are not in the picture, "
        f"starting with {missing[0]!r}. Run: {REGENERATE}")


def test_the_picture_shows_nothing_the_command_does_not_print() -> None:
    """The direction that matters most.

    A stale picture usually keeps an old line rather than losing a new one, and
    that old line is a claim about behaviour that no longer happens.
    """
    result = subprocess.run(
        [sys.executable, "-m", "clayseal.capabilities.cli", "try", "--fast"],
        cwd=ROOT, capture_output=True, text=True, timeout=120, check=False,
    )
    printed = {ln.strip() for ln in result.stdout.splitlines() if ln.strip()}
    invented = [
        ln.strip() for ln in _svg_text()
        if ln.strip() and ln.strip() != "clayseal try" and ln.strip() not in printed
    ]
    assert not invented, (
        f"the picture shows {invented!r}, which the command does not print. "
        f"Run: {REGENERATE}")


def test_it_is_small_enough_to_put_in_a_readme() -> None:
    """Text, so it should stay tiny. A jump means somebody pasted a raster in."""
    size = SVG.stat().st_size
    assert size < 128 * 1024, f"{size} bytes is too big for a README image"


def test_the_readme_actually_shows_it() -> None:
    readme = (ROOT / "README.md").read_text()
    assert "docs/assets/clayseal-try.svg" in readme
    # An image carrying the whole first impression needs alt text, and a
    # generic one is the same as none.
    tag = re.search(r'<img src="docs/assets/clayseal-try\.svg"[^>]*>', readme)
    assert tag, "the picture is referenced without an img tag to check"
    alt = re.search(r'alt="([^"]*)"', tag.group(0))
    assert alt and len(alt.group(1)) > 40, "the picture needs real alt text"


@pytest.mark.parametrize("colour", ["#d29a72", "#7cb87c", "#e07a6a"])
def test_the_verdicts_are_still_colour_coded(colour: str) -> None:
    """Clay for the brand, green for allowed, red for refused.

    Pinned because the escape-code parser is the part most likely to break
    silently: a picture with the colours dropped still renders and still reads
    as correct.
    """
    assert colour in SVG.read_text(), f"{colour} is gone; run: {REGENERATE}"
