"""The ceiling has to survive a second process, not just a second thread.

`PrincipalLedger` synchronises on a `threading.RLock`. Measured before
`SharedPrincipalLedger` existed, four OS processes against one ledger file and a
ceiling of 100: **400 landed**. Each process loaded the log, saw nothing spent,
reserved, and committed, the same check-then-act race `reserve` already fixes
for threads, one layer out.

It is the gap that mattered most, because every claim this repository makes about
cumulative authorization was measured in a single process, and no real deployment
runs that way. A second gunicorn worker or k8s replica is a second ceiling, which
is the session-restart escape `principal_ledger.py` was written to close,
arriving through the process table instead of the session.

Real subprocesses, not threads: a threading test cannot fail the way this
failed. Each spawns a fresh interpreter, so nothing is shared except the files.
"""
from __future__ import annotations

import subprocess
import sys
import textwrap
from decimal import Decimal

import pytest

from clayseal.capabilities.principal_ledger import SharedPrincipalLedger

pytestmark = pytest.mark.skipif(
    not hasattr(__import__("fcntl", fromlist=["flock"]), "flock"),
    reason="POSIX file locking required")


def _run_workers(path, n_procs: int, per_proc: int, amount: str,
                 ceiling: str) -> None:
    """Spawn `n_procs` interpreters that each try `per_proc` reservations."""
    script = textwrap.dedent(f"""
        from decimal import Decimal
        from pathlib import Path
        from clayseal.capabilities.principal_ledger import SharedPrincipalLedger
        led = SharedPrincipalLedger(path=Path({str(path)!r}))
        for _ in range({per_proc}):
            h = led.reserve("p", "usd", Decimal({amount!r}), Decimal({ceiling!r}))
            if h is not None:
                led.commit_hold(h, session="w")
    """)
    procs = [subprocess.Popen([sys.executable, "-c", script])
             for _ in range(n_procs)]
    for proc in procs:
        assert proc.wait(timeout=120) == 0


def test_four_processes_cannot_each_spend_the_whole_ceiling(tmp_path):
    """The exact scenario that measured 400 against a ceiling of 100."""
    path = tmp_path / "ledger.jsonl"
    _run_workers(path, n_procs=4, per_proc=1, amount="100", ceiling="100")
    final = SharedPrincipalLedger(path=path)
    assert final.spent("p", "usd") == Decimal(100)


def test_sixteen_processes_structuring_small_amounts(tmp_path):
    """800 demanded in 10-unit slices; exactly the ceiling may land.

    Small amounts are the harder case: one big request is refused by any check
    that runs at all, while eighty small ones need the shared total to be
    correct on every single pass.
    """
    path = tmp_path / "ledger.jsonl"
    _run_workers(path, n_procs=16, per_proc=5, amount="10", ceiling="100")
    final = SharedPrincipalLedger(path=path)
    assert final.spent("p", "usd") == Decimal(100)
    assert final.verify_totals()


def test_an_uncommitted_hold_in_another_process_still_blocks(tmp_path):
    """Holds must be shared, not only committed spend.

    This is the part a shared log alone does not fix. Two processes that each
    hold a reservation cannot see each other's, so both pass the ceiling check
    and both commit later, the ledger ends up over its ceiling with every
    individual decision having looked correct.
    """
    path = tmp_path / "ledger.jsonl"
    holder = SharedPrincipalLedger(path=path)
    assert holder.reserve("p", "usd", Decimal(100), Decimal(100)) is not None

    other = SharedPrincipalLedger(path=path)
    assert other.reserve("p", "usd", Decimal(10), Decimal(100)) is None


def test_a_release_in_one_process_frees_headroom_in_another(tmp_path):
    """The false-block direction, and it caught a real bug.

    The base class pops holds by object identity, which is right in-process and
    wrong here: after syncing, the list holds reconstructed Hold objects for the
    same reservation, so `is` never matches and the headroom is never returned.
    `SharedPrincipalLedger.release` matches on `hold_id` as well.
    """
    path = tmp_path / "ledger.jsonl"
    first = SharedPrincipalLedger(path=path)
    hold = first.reserve("p", "usd", Decimal(100), Decimal(100))

    blocked = SharedPrincipalLedger(path=path)
    assert blocked.reserve("p", "usd", Decimal(50), Decimal(100)) is None

    first.release(hold)

    freed = SharedPrincipalLedger(path=path)
    assert freed.reserve("p", "usd", Decimal(50), Decimal(100)) is not None


def test_commits_from_another_process_are_visible(tmp_path):
    path = tmp_path / "ledger.jsonl"
    writer = SharedPrincipalLedger(path=path)
    hold = writer.reserve("p", "usd", Decimal(60), Decimal(100))
    writer.commit_hold(hold, session="w")

    reader = SharedPrincipalLedger(path=path)
    assert reader.spent("p", "usd") == Decimal(60)
    assert reader.reserve("p", "usd", Decimal(50), Decimal(100)) is None
    assert reader.reserve("p", "usd", Decimal(40), Decimal(100)) is not None


def test_a_long_lived_instance_sees_later_writes(tmp_path):
    """The in-memory index is a snapshot; every transaction must tail the log.

    A server process holds one ledger for its lifetime, so 'read it at startup'
    is the same bug as not sharing at all, it just takes longer to show up.
    """
    path = tmp_path / "ledger.jsonl"
    long_lived = SharedPrincipalLedger(path=path)
    assert long_lived.spent("p", "usd") == Decimal(0)

    other = SharedPrincipalLedger(path=path)
    other.commit_hold(other.reserve("p", "usd", Decimal(70), Decimal(100)),
                      session="o")

    assert long_lived.spent("p", "usd") == Decimal(70)


def test_it_refuses_to_be_built_without_a_path():
    """The file IS the shared state, so an in-memory shared ledger is a lie."""
    with pytest.raises(ValueError, match="path"):
        SharedPrincipalLedger()


# --------------------------------------------------------------------------- #
# The backend is a dependency, so it can be down
# --------------------------------------------------------------------------- #
import os
import stat

from clayseal.capabilities.principal_ledger import (
    LedgerUnavailable,
    PrincipalBudgetView,
)


def _unreachable(tmp_path, **kw):
    """A ledger whose lock file cannot be created."""
    path = tmp_path / "l.jsonl"
    ledger = SharedPrincipalLedger(path=path, **kw)
    os.chmod(tmp_path, stat.S_IRUSR | stat.S_IXUSR)
    return ledger


def _view(ledger):
    return PrincipalBudgetView(
        ledger=ledger, principal="p", ceilings={"usd": Decimal(100)},
        tracked={"payments.transfer": ("amount", "usd")}, session="s")


def test_an_unreachable_backend_refuses_and_says_so(tmp_path):
    """Fail closed, and distinguishably.

    Before this the raw `PermissionError` escaped the authorization path. That
    is fail-closed only by accident: it takes the request down, it cannot be
    told from a bug, and nothing counts it.
    """
    ledger = _unreachable(tmp_path)
    try:
        allowed, reason = _view(ledger).authorize(
            "payments.transfer", {"amount": "10"})
        assert not allowed
        assert "cannot reach the shared ledger" in reason
        assert ledger.unavailable_count == 1
    finally:
        os.chmod(tmp_path, stat.S_IRWXU)


def test_the_allow_policy_exists_but_is_never_the_default(tmp_path):
    """Availability is sometimes worth more than a ceiling, but say so aloud."""
    assert SharedPrincipalLedger(path=tmp_path / "d.jsonl").on_unavailable == "deny"

    ledger = _unreachable(tmp_path, on_unavailable="allow")
    try:
        allowed, _ = _view(ledger).authorize("payments.transfer", {"amount": "10"})
        assert allowed
        # Still counted. The point of the flag is a known risk, not a hidden one.
        assert ledger.unavailable_count == 1
    finally:
        os.chmod(tmp_path, stat.S_IRWXU)


def test_one_refused_action_counts_as_one_outage(tmp_path):
    """`reserve` calls `spent`, which opens its own transaction.

    Without re-entrancy on the failure path, one action reported two outages
    the kind of inflated number an operator learns to ignore, on the one metric
    that says the ceiling stopped being enforced.
    """
    ledger = _unreachable(tmp_path, on_unavailable="allow")
    try:
        _view(ledger).authorize("payments.transfer", {"amount": "10"})
        assert ledger.unavailable_count == 1
    finally:
        os.chmod(tmp_path, stat.S_IRWXU)


def test_the_exception_type_is_specific(tmp_path):
    ledger = _unreachable(tmp_path)
    try:
        with pytest.raises(LedgerUnavailable):
            ledger.reserve("p", "usd", Decimal(1), Decimal(100))
    finally:
        os.chmod(tmp_path, stat.S_IRWXU)


# --------------------------------------------------------------------------- #
# Operational visibility
# --------------------------------------------------------------------------- #
def test_health_reports_a_breach_that_would_otherwise_be_invisible(tmp_path):
    """A ceiling was exceeded and nothing said so.

    `late_breaches` recorded it from the day it was added and surfaced it
    nowhere. A control whose failures are only discoverable by reading the
    source is not an operable control.
    """
    ledger = SharedPrincipalLedger(path=tmp_path / "l.jsonl",
                                   reservation_ttl_seconds=60.0)
    first = ledger.reserve("p", "usd", Decimal(100), Decimal(100), now=0.0)
    second = ledger.reserve("p", "usd", Decimal(100), Decimal(100), now=120.0)
    ledger.commit_hold(first, now=121.0)
    ledger.commit_hold(second, now=122.0)

    health = ledger.health()
    assert health["late_breaches"] == 1
    assert health["late_breach_value"] == "100"
    assert health["totals_verified"] is True
    assert health["cross_process"] is True


def test_health_reports_backend_outages(tmp_path):
    ledger = _unreachable(tmp_path, on_unavailable="allow")
    try:
        _view(ledger).authorize("payments.transfer", {"amount": "10"})
    finally:
        os.chmod(tmp_path, stat.S_IRWXU)
    assert ledger.health()["unavailable"] == 1


def test_a_quiet_ledger_reports_nothing_alarming(tmp_path):
    """The false-alarm side: a healthy ledger must not look unhealthy."""
    ledger = SharedPrincipalLedger(path=tmp_path / "l.jsonl")
    ledger.commit_hold(
        ledger.reserve("p", "usd", Decimal(10), Decimal(100)), session="s")
    health = ledger.health()
    assert health["late_breaches"] == 0
    assert health["unavailable"] == 0
    assert health["totals_verified"] is True
    assert health["entries"] == 1


def test_health_is_serialisable(tmp_path):
    """Whatever the deployment scrapes, it has to be able to scrape this."""
    import json

    ledger = SharedPrincipalLedger(path=tmp_path / "l.jsonl")
    json.dumps(ledger.health())


def test_a_released_hold_is_not_resurrected_by_another_process(tmp_path):
    """Phantom holds: the failure that under-grants instead of over-granting.

    An earlier `_load_sidecar` merged this instance's `self._holds` back on top
    of the sidecar, meaning to preserve its own Hold objects. But after a sync
    `self._holds` holds *every* process's reservations, so the merge resurrected
    holds their owners had already released. Measured across 16 processes: five
    phantom holds pinning 50 of a 100 ceiling, and 70 landing where 100 should
    have.

    It is worth a test of its own because it fails in the safe direction and so
    hides: the ceiling is never breached, the system just quietly refuses honest
    work, and every individual decision looks correct.
    """
    path = tmp_path / "l.jsonl"
    first = SharedPrincipalLedger(path=path)
    second = SharedPrincipalLedger(path=path)

    hold = first.reserve("p", "usd", Decimal(50), Decimal(100))
    # `second` syncs and now carries a copy of first's hold in its own `_holds`.
    assert second.reserve("p", "usd", Decimal(60), Decimal(100)) is None

    first.release(hold)

    # If `second` re-merges its stale copy, the 50 stays pinned forever.
    assert second.reserve("p", "usd", Decimal(100), Decimal(100)) is not None


def test_the_sidecar_is_empty_once_everything_is_committed(tmp_path):
    """Nothing outstanding must survive a completed workload."""
    path = tmp_path / "l.jsonl"
    _run_workers(path, n_procs=8, per_proc=2, amount="10", ceiling="100")
    final = SharedPrincipalLedger(path=path)
    assert final.health()["outstanding_holds"] == 0
    assert final.spent("p", "usd") == Decimal(100)
