"""The adaptive ladder, and the invariant that keeps it honest.

The literature's finding is that static benchmarks under-measure: twelve in-band
defenses looked strong until adaptive attacks broke them at over 90%. This suite
replayed attacks its own authors wrote, so validity gate P10 failed until this
existed.
"""
import pytest

from benchmarks.adaptive_bpl import LEVELS, _strategies, attack
from benchmarks.live.bpl_live import get_scenario

SAMPLE = ["payout-splitting", "retry-storm-double-effect",
          "contractor-scope-creep", "bulk-exfil"]


def test_the_knowledge_levels_are_nested():
    """A better-informed attacker can do everything a weaker one can.

    The first version picked one strategy per level independently, and the
    monotonicity check caught it at once: `feedback` held 37 scenarios where
    `blind` held 36. That is not a fact about the defense — the stronger
    attacker had simply drawn from a different bag.
    """
    reasons = ["budget_exceeded", "duplicate_effect", "velocity"]
    sets = [set(map(id, _strategies(lv, reasons))) for lv in LEVELS]
    for weaker, stronger in zip(sets, sets[1:]):
        assert weaker <= stronger


@pytest.mark.parametrize("name", SAMPLE)
def test_containment_is_monotone_in_attacker_knowledge(name):
    """If a stronger attacker does worse, the harness is wrong."""
    scen = get_scenario(name)
    held = [not attack(scen, lv, rounds=6, seed=0)["escaped"] for lv in LEVELS]
    # True (held) must never follow False (escaped) as knowledge rises.
    for weaker, stronger in zip(held, held[1:]):
        assert not (stronger and not weaker), (name, held)


def test_the_search_actually_finds_something():
    """A search that never escapes proves nothing about the defense.

    `contractor-scope-creep` is the case: its fix was fitted to the scripted
    sequence — once-per-person, when the objective is any write-level grant —
    and varying the person walks straight through.
    """
    scen = get_scenario("contractor-scope-creep")
    assert attack(scen, "oracle", rounds=10, seed=0)["escaped"]


def test_a_ledger_governed_scenario_holds_at_every_level():
    """The contrast. `retry-storm`'s objective IS a duplicate effect, so the
    once-per-object mandate expresses it rather than approximating it, and no
    amount of mutation helps."""
    scen = get_scenario("retry-storm-double-effect")
    for level in LEVELS:
        assert not attack(scen, level, rounds=10, seed=0)["escaped"], level
