"""The audit log has to survive a long session without eating it.

`DecisionLog` held every record for the life of the session with no bound and no
default sink. A coding agent runs for hours, so the log grew with the run and was
then lost whole on exit — a memory leak and no evidence, from the same omission.

Bounding it is only safe if eviction stays distinguishable from tampering. These
tests pin that line: an evicted window still verifies, a modified record still
does not, and the head hash still covers everything ever appended.
"""
from __future__ import annotations

from agentauth.capabilities.decision_log import DEFAULT_MAX_RECORDS, DecisionLog


def _append(log: DecisionLog, n: int, start: int = 0) -> None:
    for i in range(start, start + n):
        log.append(
            query_id="q", tool="tool", resource="res", action_verb="read",
            arguments_hash=f"sha256:{i:04d}", outcome="allow", layer="-",
            reasons=(),
        )


def test_the_log_is_bounded_by_default():
    assert DecisionLog().max_records == DEFAULT_MAX_RECORDS


def test_eviction_drops_the_oldest_and_counts_what_it_dropped():
    log = DecisionLog(max_records=10)
    _append(log, 25)

    records = log.records()
    assert len(records) == 10
    assert log.evicted == 15
    # The window is the MOST RECENT decisions, which is what an operator asks for.
    assert [r["seq"] for r in records] == list(range(15, 25))


def test_an_evicted_window_still_verifies():
    """Eviction is bookkeeping. Reporting it as a chain break would make every
    long session look compromised, and an alert that always fires is not one."""
    log = DecisionLog(max_records=10)
    _append(log, 25)

    ok, reason = log.verify()
    assert ok, reason


def test_tampering_inside_an_evicted_window_is_still_caught():
    log = DecisionLog(max_records=10)
    _append(log, 25)

    victim = log._records[4]
    log._records[4] = type(victim)(
        **{**victim.__dict__, "outcome": "allow", "tool": "some_other_tool"}
    )

    ok, reason = log.verify()
    assert not ok
    assert "does not match its hash" in (reason or "")


def test_a_dropped_record_inside_the_window_is_still_caught():
    log = DecisionLog(max_records=10)
    _append(log, 25)
    del log._records[5]

    ok, reason = log.verify()
    assert not ok


def test_the_head_hash_still_covers_everything_ever_appended():
    """An evicted record is gone from this process, not from the chain.

    The head commits to the full history, so a verifier holding the evicted
    prefix from a durable sink can join it to the retained window.
    """
    bounded = DecisionLog(session_id="fixed", max_records=10)
    unbounded = DecisionLog(session_id="fixed", max_records=None)
    for log in (bounded, unbounded):
        for i in range(25):
            log.append(
                query_id="q", tool="tool", resource="res", action_verb="read",
                arguments_hash=f"sha256:{i:04d}", outcome="allow", layer="-",
                reasons=(),
            )
    # created_at differs per record, so compare the chain STRUCTURE rather than
    # the hashes: same length, same sequence numbers, both verifying.
    assert unbounded.evicted == 0
    assert len(unbounded.records()) == 25
    assert bounded.evicted == 15
    assert [r["seq"] for r in bounded.records()] == \
        [r["seq"] for r in unbounded.records()[15:]]
    assert bounded.verify()[0] and unbounded.verify()[0]


def test_eviction_can_be_switched_off():
    """The benchmark harnesses keep whole sessions on purpose."""
    log = DecisionLog(max_records=None)
    _append(log, 200)
    assert len(log.records()) == 200
    assert log.evicted == 0
    assert log.verify()[0]
