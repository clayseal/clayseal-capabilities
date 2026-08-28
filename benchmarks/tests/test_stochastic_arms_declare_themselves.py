"""An arm that is not a function of the seed has to say so.

`benchmarks/flow.py` races writers through a thread pool for its concurrent
arms. Thread interleaving is not seedable, and the arm exists to catch a lost
update, so making it deterministic would delete the thing it measures. Two runs
of the same commit give 170/200 and 155/200 for the same cell.

Those arms used to be published as a single pooled count with no spread, which
is a draw from a distribution presented as a measurement. It caused a false
regression during a performance pass: 150/200 to 158/200 read as containment
getting worse, and it was noise. The mirror failure is worse — a real 8-point
regression dismissed by someone who had learned the arm was unreliable.

So the instrument declares it. This asserts that it still does, and that the
declaration is attached to the arms that need it and not to the ones that do not:
a `NOT SEEDED` label on a deterministic arm would train readers to ignore the
label, which is the same failure one step removed.
"""
from __future__ import annotations

import pytest

from benchmarks.flow import SplitTally


def _tally(per_trial: dict[int, list[int]]) -> SplitTally:
    tally = SplitTally()
    tally.per_trial = per_trial
    tally.sessions = sum(n for _, n in per_trial.values())
    tally.whole_out = sum(out for out, _ in per_trial.values())
    return tally


def test_a_multi_trial_arm_declares_itself_not_seeded():
    tally = _tally({0: [39, 50], 1: [41, 50], 2: [40, 50], 3: [39, 50]})
    assert tally.is_stochastic
    note = tally.spread_note()
    assert "NOT SEEDED" in note
    assert "39-41 of 50" in note, note
    assert "compare distributions, not runs" in note


def test_a_seeded_arm_says_nothing():
    """The label has to mean something. Putting it on a deterministic arm
    teaches readers to skip it."""
    assert _tally({}).spread_note() == ""
    assert _tally({0: [12, 50]}).spread_note() == "", "one trial is not a spread"
    assert not _tally({0: [12, 50]}).is_stochastic


def test_the_json_marks_it_too():
    """A reader of the JSON has no prose to fall back on, so the flag has to be
    in the payload rather than only in the printed table."""
    stochastic = _tally({0: [39, 50], 1: [41, 50]}).as_dict()
    assert stochastic["stochastic"] is True
    assert stochastic["per_trial_whole_out"] == [39, 41]
    assert stochastic["per_trial_sessions"] == 50

    seeded = _tally({}).as_dict()
    assert "stochastic" not in seeded
    assert "per_trial_whole_out" not in seeded


def test_the_pooled_count_still_matches_the_trials():
    """The spread is an addition, not a replacement: the headline count must
    still be the sum of what the trials saw, or the two disagree in public."""
    tally = _tally({0: [39, 50], 1: [41, 50], 2: [40, 50], 3: [39, 50]})
    assert tally.whole_out == sum(tally.as_dict()["per_trial_whole_out"])
    assert tally.sessions == 200


def test_add_records_a_trial_only_when_given_one():
    """`add` is called by both the seeded and the concurrent paths. Tagging the
    seeded ones would mislabel them as stochastic."""
    seeded = SplitTally()
    seeded.add([True, True])
    seeded.add([True, False])
    assert not seeded.is_stochastic
    assert seeded.whole_out == 1 and seeded.sessions == 2

    raced = SplitTally()
    raced.add([True, True], trial=0)
    raced.add([True, True], trial=1)
    assert raced.is_stochastic
    assert raced.trial_rates == [1.0, 1.0]


@pytest.mark.parametrize("arm", ["concurrent chunked", "concurrent fan-out"])
def test_the_concurrent_arms_are_still_the_ones_being_tagged(arm):
    """Guard against the tagging being dropped from the caller.

    Every assertion above tests `SplitTally` in isolation and would pass if
    `evaluate()` stopped passing `trial=`. This reads the source of the call
    site instead, which is cheap and does not need a 200-session run.
    """
    import inspect

    from benchmarks import flow

    source = inspect.getsource(flow.evaluate)
    assert "trial=trial" in source, (
        "the concurrent arms are no longer tagged by trial, so their spread "
        "will not be reported and the pooled count reads as repeatable")
    assert arm in inspect.getsource(flow)
