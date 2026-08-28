"""The README's test-count badge has to be a floor the suite actually clears.

It said "2,244 passing" and CONTRIBUTING said "~1,650" while the suite collected
2,376. Nobody was misled by much, but a number in a README that nobody checks is
a number that drifts, and this repository asks readers to check its numbers.

The badge is written as a floor (`2300+`) rather than an exact count on purpose:
an exact count has to be edited by every pull request that adds a test, which is
how it fell out of date in the first place. A floor only needs attention when it
is crossed, and the assertion below can only fail in two ways, both of which are
worth a look:

- tests were deleted, dropping the suite under the advertised floor
- the suite grew a lot and the badge is now underselling it by more than a
  thousand, which usually means someone bumped the floor and forgot the badge

`--collect-only` is used rather than a run, so this costs a collection rather
than a second full pass over the suite.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"
TESTS = ROOT / "python" / "tests"

_BADGE = re.compile(r"img\.shields\.io/badge/tests-([0-9]+)(?:%2B|\+)")


def _advertised_floor() -> int:
    match = _BADGE.search(README.read_text())
    assert match, "the README no longer has a tests badge in the expected form"
    return int(match.group(1))


def _collected() -> int:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(TESTS), "-q", "--collect-only",
         "-p", "no:cacheprovider"],
        capture_output=True, text=True, cwd=ROOT, check=False,
    )
    match = re.search(r"(\d+) tests collected", proc.stdout)
    if not match:
        pytest.skip(f"could not read a collection count: {proc.stdout[-400:]}")
    return int(match.group(1))


def test_the_suite_clears_the_floor_the_readme_advertises():
    floor, collected = _advertised_floor(), _collected()
    assert collected >= floor, (
        f"README advertises {floor}+ tests; the suite collects {collected}. "
        "Either tests were deleted, or the badge needs lowering to the truth."
    )


def test_the_floor_is_not_wildly_stale():
    """A floor a thousand under the real count is not a floor, it is a fossil."""
    floor, collected = _advertised_floor(), _collected()
    assert collected - floor < 1000, (
        f"README advertises {floor}+ but the suite collects {collected}. "
        f"Raise the badge to {(collected // 100) * 100}+."
    )
