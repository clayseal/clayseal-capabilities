"""`clayseal try` is the first thing anyone runs, so it is the first thing to pin.

A tour that prints a convincing transcript while the gateway underneath has
stopped working is worse than no tour. Every verdict in it comes from a live
`SessionBroker`, and these tests check that the verdicts are real and that the
output stays readable when nobody is watching it in a terminal.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def tour() -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "clayseal.capabilities.cli", "try", "--fast"],
        cwd=REPO, capture_output=True, text=True, timeout=120, check=False,
    )


def test_the_tour_exits_clean(tour) -> None:
    """Non-zero means the gateway failed to stop what the tour says it stops.

    `run()` returns 1 unless ten refunds were refused and the injected send was
    held, so this asserts the demonstration rather than the printing.
    """
    assert tour.returncode == 0, tour.stdout + tour.stderr


def test_the_budget_attack_is_actually_refused(tour) -> None:
    assert "REFUSED" in tour.stdout
    assert "$9,000 stayed where it was" in tour.stdout


def test_the_injected_destination_is_held(tour) -> None:
    assert "HELD" in tour.stdout
    assert "collector-metrics.example" in tour.stdout


def test_it_never_pauses_when_nobody_is_there(tour) -> None:
    """A tour that blocks on input hangs CI and hangs a pipe.

    The run above passes no stdin and captures stdout, so a `wait()` that did
    not check for a terminal would hang until the timeout.
    """
    assert "press enter" not in tour.stdout


def test_it_emits_no_escape_codes_when_piped(tour) -> None:
    """Captured output is not a terminal, so colour has to be off.

    Checked because the colour decision and the pacing decision are the same
    branch: if this fails, the tour is also sleeping through a CI run.
    """
    assert "\033[" not in tour.stdout


def test_explain_names_the_layer_that_answered() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "clayseal.capabilities.cli",
         "try", "--fast", "--explain"],
        cwd=REPO, capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "answered by the floor" in result.stdout
    # The machine-readable reason belongs here and not in the default tour,
    # where it was the only line a newcomer could not read.
    assert "value_budget_exceeded" in result.stdout


def test_the_plain_tour_hides_the_reason_codes(tour) -> None:
    assert "value_budget_exceeded" not in tour.stdout


def test_the_tour_points_at_policy_new_next() -> None:
    """The next command after the demo is the one that does not need a server."""
    result = subprocess.run(
        [sys.executable, "-m", "clayseal.capabilities.cli", "try", "--fast"],
        cwd=REPO, capture_output=True, text=True, timeout=120, check=False,
    )
    assert "clayseal policy new" in result.stdout
    assert "clayseal howto" in result.stdout


def test_no_args_points_at_the_demo() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "clayseal.capabilities.cli"],
        cwd=REPO, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0
    assert "clayseal try" in result.stderr
    assert "clayseal howto" in result.stderr
    assert "usage:" in result.stdout.lower() or "usage:" in result.stderr.lower()
