"""The ceiling curve, pinned in both directions plus its own controls.

A benchmark that only checks the system under test is one that cannot tell a
result from a tautology. `deny-all` and `allow-all` are asserted here for the
same reason `ceiling_proximity.py` prints them: each wins one column trivially,
so a ledger row that matches either is not a result.
"""
from decimal import Decimal

import pytest

from benchmarks.ceiling_proximity import (
    CEILING,
    SHAPES,
    run_allow_all,
    run_deny_all,
    run_ledger,
    sweep,
)


@pytest.mark.parametrize("name", sorted(SHAPES))
@pytest.mark.parametrize("ratio", ["0.25", "0.90", "0.99", "1.00"])
def test_demand_that_fits_is_never_blocked(name, ratio):
    total = (CEILING * Decimal(ratio)).quantize(Decimal("0.01"))
    landed, blocked = run_ledger(SHAPES[name](total, 20))
    assert blocked == 0, f"{name} at {ratio} blocked honest work"
    assert landed == total


@pytest.mark.parametrize("name", sorted(SHAPES))
@pytest.mark.parametrize("ratio", ["1.01", "1.25", "2.00"])
def test_demand_that_does_not_fit_never_exceeds_the_ceiling(name, ratio):
    total = (CEILING * Decimal(ratio)).quantize(Decimal("0.01"))
    landed, _blocked = run_ledger(SHAPES[name](total, 20))
    assert landed <= CEILING, f"{name} at {ratio} landed {landed}"


@pytest.mark.parametrize("name", sorted(SHAPES))
def test_every_shape_sums_to_its_requested_total(name):
    """The generator must be exact, or the benchmark grades the wrong thing.

    Rounding each element independently left `front-loaded` at ratio 1.00
    requesting 1000.01 against a ceiling of 1000. The ledger correctly refused
    the last cent and the harness scored it as a false block, because it had
    labelled that demand as fitting. One cent of generator drift and the
    benchmark reports a defect in the system under test.
    """
    for ratio in ("0.25", "0.99", "1.00", "1.05", "2.00"):
        total = (CEILING * Decimal(ratio)).quantize(Decimal("0.01"))
        assert sum(SHAPES[name](total, 20)) == total, ratio


def test_the_controls_each_fail_the_column_they_do_not_win():
    """Neither control may pass both halves, or the benchmark is not measuring."""
    over = (CEILING * Decimal(2)).quantize(Decimal("0.01"))
    fits = (CEILING * Decimal("0.9")).quantize(Decimal("0.01"))

    # deny-all: holds every ceiling, refuses every honest action.
    assert run_deny_all(SHAPES["uniform"](over, 20))[0] == 0
    assert run_deny_all(SHAPES["uniform"](fits, 20))[1] == 20

    # allow-all: never blocks, and walks straight through the ceiling.
    assert run_allow_all(SHAPES["uniform"](fits, 20))[1] == 0
    assert run_allow_all(SHAPES["uniform"](over, 20))[0] > CEILING


def test_the_full_sweep_is_clean_in_both_directions():
    rows = [r for r in sweep([0.25, 0.9, 0.99, 1.0, 1.01, 1.5, 2.0], 20)
            if r["condition"] == "ledger"]
    assert sum(r["false_blocks"] for r in rows) == 0
    assert sum(r["over_ceiling"] for r in rows) == 0


def test_headroom_left_unused_is_bounded_by_one_action():
    """The honest form of the friction claim.

    Just over the ceiling the ledger lands 0.96, not 1.00, because actions are
    atomic: when the next one does not fit it is refused whole. The cost is
    bounded by the largest single action rather than by the block rate, and
    stating it that way is what stops `progress 37%` being read as the ledger
    refusing a third of honest work.
    """
    total = (CEILING * Decimal("1.01")).quantize(Decimal("0.01"))
    amounts = SHAPES["uniform"](total, 20)
    landed, _ = run_ledger(amounts)
    assert landed <= CEILING
    assert CEILING - landed < max(amounts)
