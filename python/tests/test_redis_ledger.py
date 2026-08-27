"""A ceiling that holds across machines, not just across processes.

`SharedPrincipalLedger` fixed the cross-PROCESS hole with `fcntl`, four workers
against a ceiling of 100 went from 400 landed to 100, and its docstring names
what is left: a file lock is invisible to a second machine, so a two-node
deployment is back to one ceiling per node.

These tests are the cross-HOST version of `test_shared_ledger.py`'s scenarios,
with independent client objects standing in for independent nodes.

WHAT THIS DOES AND DOES NOT PROVE
---------------------------------
They run against `fakeredis`, an in-process double. That is honest for what is
being tested, the ledger's own logic, which is where every bug in the file
backend was, and it is NOT a test of a real Redis under partition or failover.
Set `CLAYSEAL_TEST_REDIS_URL` to run the identical suite against a live server;
without it those parametrisations skip rather than passing silently.
"""
from __future__ import annotations

import os
import threading
from decimal import Decimal

import pytest

from clayseal.capabilities.ledger_backends import RedisPrincipalLedger
from clayseal.capabilities.principal_ledger import LedgerUnavailable

fakeredis = pytest.importorskip("fakeredis")

PRINCIPAL = "mandate:payroll-agent"
BUDGET = "usd-transfers"
CEILING = Decimal("100")


@pytest.fixture
def server():
    """One Redis, shared by every 'node' in a test."""
    live = os.environ.get("CLAYSEAL_TEST_REDIS_URL", "").strip()
    if live:
        import redis

        client = redis.Redis.from_url(live)
        prefix = f"agentauth:test:{os.getpid()}:{threading.get_ident()}"
        for suffix in ("lock", "log", "holds"):
            client.delete(f"{prefix}:{suffix}")
        yield lambda: (redis.Redis.from_url(live), prefix)
        for suffix in ("lock", "log", "holds"):
            client.delete(f"{prefix}:{suffix}")
        return

    shared = fakeredis.FakeServer()

    def connect():
        return fakeredis.FakeStrictRedis(server=shared), "agentauth:test"

    yield connect


def node(server, **kwargs) -> RedisPrincipalLedger:
    """A ledger with its OWN client and its own in-memory index, a second host."""
    client, prefix = server()
    return RedisPrincipalLedger(
        client=client, prefix=prefix, window_seconds=3600, **kwargs
    )


# --------------------------------------------------------------------------- #
# The headline: the ceiling survives more than one host.
# --------------------------------------------------------------------------- #
def test_four_nodes_against_one_ceiling_land_the_ceiling(server):
    """The file backend's own scenario, one layer out.

    Each 'node' has a separate client and a separate index, which is exactly
    what makes it a different machine rather than a different thread.
    """
    nodes = [node(server) for _ in range(4)]
    landed = Decimal(0)
    lock = threading.Lock()

    def spend(ledger: RedisPrincipalLedger) -> None:
        nonlocal landed
        for _ in range(25):
            hold = ledger.reserve(PRINCIPAL, BUDGET, Decimal("4"), CEILING)
            if hold is None:
                continue
            ledger.commit_hold(hold, session="w")
            with lock:
                landed += Decimal("4")

    threads = [threading.Thread(target=spend, args=(n,)) for n in nodes]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert landed <= CEILING, f"{landed} landed against a ceiling of {CEILING}"
    # And the ledger agrees with what the callers observed.
    assert nodes[0].spent(PRINCIPAL, BUDGET) == landed


def test_committed_spend_on_one_node_is_visible_on_another(server):
    """An in-memory index is a snapshot from load time.

    A server process holds one ledger for its lifetime, so "read it at startup"
    is the same bug as not sharing at all, it just takes longer to show up.
    """
    a, b = node(server), node(server)
    hold = a.reserve(PRINCIPAL, BUDGET, Decimal("90"), CEILING)
    assert hold is not None
    a.commit_hold(hold, session="node-a")

    assert b.spent(PRINCIPAL, BUDGET) == Decimal("90")
    assert b.reserve(PRINCIPAL, BUDGET, Decimal("20"), CEILING) is None


def test_an_outstanding_hold_on_one_node_blocks_another(server):
    """The subtle one a shared log alone does not fix.

    Two nodes that each hold a reservation cannot see each other's, so both pass
    the ceiling check and both commit later.
    """
    a, b = node(server), node(server)
    hold = a.reserve(PRINCIPAL, BUDGET, Decimal("80"), CEILING)
    assert hold is not None

    assert b.reserve(PRINCIPAL, BUDGET, Decimal("30"), CEILING) is None, (
        "the second node could not see the first node's outstanding hold"
    )

    a.release(hold)
    assert b.reserve(PRINCIPAL, BUDGET, Decimal("30"), CEILING) is not None


def test_a_release_on_one_node_frees_headroom_on_another(server):
    a, b = node(server), node(server)
    hold = a.reserve(PRINCIPAL, BUDGET, Decimal("100"), CEILING)
    assert hold is not None
    assert b.reserve(PRINCIPAL, BUDGET, Decimal("1"), CEILING) is None
    a.release(hold)
    assert b.reserve(PRINCIPAL, BUDGET, Decimal("1"), CEILING) is not None


def test_a_hold_released_on_another_node_is_not_resurrected(server):
    """The phantom-hold bug, in its cross-host form.

    On the file backend, merging this process's own `_holds` on top of the store
    resurrected holds their owners had already released: 5 phantoms pinning 50
    of a 100 ceiling, 70 landing where 100 should have. It failed in the SAFE
    direction, which is why it needed finding, the ceiling is never breached,
    the system quietly refuses honest work, and every decision looks correct.
    """
    a, b = node(server), node(server)
    holds = [a.reserve(PRINCIPAL, BUDGET, Decimal("10"), CEILING) for _ in range(5)]
    assert all(h is not None for h in holds)
    for h in holds:
        a.release(h)

    # `b` now syncs, and must not bring the released holds back.
    assert b.reserve(PRINCIPAL, BUDGET, Decimal("100"), CEILING) is not None


# --------------------------------------------------------------------------- #
# The lock itself.
# --------------------------------------------------------------------------- #
def test_the_lock_is_fenced_against_its_own_expiry(server):
    """Unlock must never delete a lock that is no longer ours.

    A TTL can expire while the holder is still inside the transaction, a GC
    pause, a paused container. An unconditional delete would then remove the
    lock a DIFFERENT node has since acquired, and two writers would proceed each
    believing it held it alone.
    """
    a = node(server)
    client, prefix = server()

    with a._transaction():
        # Simulate the TTL expiring under us and another node taking the lock.
        client.set(f"{prefix}:lock", "some-other-node")

    # Our release must have left the other node's lock alone.
    held = client.get(f"{prefix}:lock")
    assert held is not None, "we deleted a lock that was not ours"
    assert held.decode() if isinstance(held, bytes) else held == "some-other-node"


def test_the_lock_is_released_on_the_happy_path(server):
    a = node(server)
    client, prefix = server()
    with a._transaction():
        assert client.get(f"{prefix}:lock") is not None
    assert client.get(f"{prefix}:lock") is None


def test_the_transaction_is_reentrant(server):
    """`reserve` calls `spent`, which opens its own transaction."""
    a = node(server)
    with a._transaction():
        with a._transaction():
            pass
    # Still usable afterwards: the inner exit did not release the outer lock.
    assert a.reserve(PRINCIPAL, BUDGET, Decimal("1"), CEILING) is not None


# --------------------------------------------------------------------------- #
# The backend is a dependency, so it can be down.
# --------------------------------------------------------------------------- #
class _Broken:
    """A client whose every call fails, like an unreachable server."""

    def __getattr__(self, _name):
        def _raise(*_a, **_k):
            raise ConnectionError("redis is unreachable")

        return _raise


def test_an_unreachable_backend_denies_by_default_and_counts_it():
    ledger = RedisPrincipalLedger(client=_Broken(), prefix="x")
    with pytest.raises(LedgerUnavailable, match="cannot reach the shared ledger"):
        ledger.reserve(PRINCIPAL, BUDGET, Decimal("1"), CEILING)
    assert ledger.unavailable_count >= 1


def test_allow_on_unavailable_is_opt_in_and_counted():
    """Availability is sometimes worth more than a ceiling. It is never implicit."""
    ledger = RedisPrincipalLedger(
        client=_Broken(), prefix="x", on_unavailable="allow"
    )
    hold = ledger.reserve(PRINCIPAL, BUDGET, Decimal("1"), CEILING)
    assert hold is not None                      # proceeded on this node's view
    assert ledger.unavailable_count >= 1         # and said so


def test_one_refused_action_counts_as_one_outage():
    """`reserve` calls `spent`, which opens its own transaction.

    Without re-entrancy on the FAILURE path one action reports two outages,
    which is the kind of inflated number an operator learns to ignore on the one
    metric that says the ceiling stopped being enforced.
    """
    ledger = RedisPrincipalLedger(
        client=_Broken(), prefix="x", on_unavailable="allow"
    )
    ledger.reserve(PRINCIPAL, BUDGET, Decimal("1"), CEILING)
    assert ledger.unavailable_count == 1


def test_a_missing_client_is_refused_at_construction():
    """Never silently degrade to an in-memory ledger: it would look like success."""
    with pytest.raises(ValueError, match="needs a client"):
        RedisPrincipalLedger(client=None)


def test_health_reports_the_backend_and_its_outages(server):
    a = node(server)
    a.reserve(PRINCIPAL, BUDGET, Decimal("1"), CEILING)
    health = a.health()
    assert health["backend"] == "redis"
    assert health["cross_host"] is True
    assert health["unavailable"] == 0
