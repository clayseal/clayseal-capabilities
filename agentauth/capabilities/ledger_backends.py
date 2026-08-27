"""A principal ledger whose ceiling holds across MACHINES, not just processes.

`SharedPrincipalLedger` closed the cross-process hole with `fcntl` and a sidecar
file, four workers against a ceiling of 100 went from 400 landed to 100. Its own
docstring names the remaining limit: *"POSIX only, single host. For multiple
hosts the same `_transaction` seam takes a Redis or Postgres lock instead."* A
file lock is invisible to a second machine, so a two-node deployment is back to
one ceiling per node, which is the session-restart escape arriving through the
load balancer instead of the process table.

This is that backend. It overrides exactly the five storage primitives and
inherits every line of reservation, ceiling and settlement logic, so the
behaviour that was measured on the file backend is the behaviour here:

    _transaction   an `fcntl` flock          -> a Redis lock (SET NX PX + fenced unlock)
    _sync_log      tail a file by byte offset -> tail a LIST by index
    _append        advance the byte offset    -> advance the list index
    _load_sidecar  read a JSON file           -> read a JSON string key
    _save_sidecar  atomic rename              -> SET

THE THREE THINGS THAT HAVE TO BE SHARED
---------------------------------------
Unchanged from the file backend, because they are properties of the problem and
not of the medium. Missing any one leaves the hole open.

**Mutual exclusion**, so the read-modify-write in `reserve` is atomic across
nodes. **Committed spend**, because an in-memory index is a snapshot from load
time and a server process holds one ledger for its lifetime. **Outstanding
holds**, the subtle one: two nodes that each hold a reservation cannot see each
other's, so both pass the ceiling check and both commit later.

WHY THE LOCK IS FENCED
----------------------
A distributed lock with a TTL can expire while its holder is still working, a
GC pause, a slow disk, a paused container. If unlock then deletes the key
unconditionally, it deletes a lock a DIFFERENT node has since acquired, and two
writers proceed believing they are alone. So each acquisition writes a unique
token and unlock is a compare-and-delete under `WATCH`: this node deletes only
its own lock, and a lock that expired under it is simply not deleted by it.

That is the standard single-instance Redis lock. It is NOT Redlock, and it does
not claim Redlock's multi-master guarantees: against a Redis failover that loses
the lock key, two holders are possible. For a spend ceiling that is the right
trade, the failure needs a failover inside one transaction window, but it is
stated rather than implied, because `on_unavailable` exists precisely so an
operator can decide what a degraded backend means.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from agentauth.capabilities.principal_ledger import (
    Hold,
    LedgerEntry,
    LedgerUnavailable,
    PrincipalLedger,
)

#: Environment variables a deployment configures the backend from, mirroring the
#: names `used_token_store` already uses so one deployment configures both.
LEDGER_REDIS_URL_ENV = "AGENTAUTH_LEDGER_REDIS_URL"
LEDGER_REDIS_PREFIX_ENV = "AGENTAUTH_LEDGER_REDIS_PREFIX"


@dataclass
class RedisPrincipalLedger(PrincipalLedger):
    """Cross-HOST principal ledger over a single Redis.

    ``client`` is anything speaking the `redis-py` subset used here: ``set`` with
    ``nx``/``px``, ``transaction``, ``rpush``, ``lrange``, ``llen``, ``get``,
    ``delete``. The package does not import ``redis``, pass a client in, the way
    ``RedisUsedTokenStore`` does.
    """

    client: Any = None
    #: Namespace for this ledger's three keys. Two ledgers sharing a prefix would
    #: share a ceiling, which is occasionally what you want and never what you
    #: want by accident, so it is explicit.
    prefix: str = "agentauth:ledger"
    #: How long a held lock survives if its holder dies. Long enough that a slow
    #: transaction does not lose it; short enough that a dead node does not pin
    #: the ceiling for everyone. A transaction here is a few small reads.
    lock_ttl_ms: int = 10_000
    #: How long to wait to acquire before declaring the backend unavailable.
    lock_wait_seconds: float = 5.0
    #: Same contract as `SharedPrincipalLedger`: "deny" refuses and counts,
    #: "allow" proceeds on this node's view and counts. Never silently chosen.
    on_unavailable: str = "deny"
    unavailable_count: int = 0
    _offset: int = 0
    _in_txn: bool = field(default=False, repr=False)

    def __post_init__(self) -> None:
        if self.client is None:
            raise ValueError(
                "RedisPrincipalLedger needs a client: the Redis IS the shared "
                "state. Use PrincipalLedger for an in-memory ledger, or "
                "SharedPrincipalLedger for several processes on one host."
            )
        # Deliberately NOT `super().__post_init__()`, for the same reason
        # `SharedPrincipalLedger` skips it: the load must happen under the lock,
        # inside the first transaction, or entries appended between the read and
        # the offset calculation are skipped forever, spend this node cannot
        # see, and therefore headroom it would grant twice.
        self._offset = 0

    # -- keys -------------------------------------------------------------- #
    @property
    def _lock_key(self) -> str:
        return f"{self.prefix}:lock"

    @property
    def _log_key(self) -> str:
        return f"{self.prefix}:log"

    @property
    def _holds_key(self) -> str:
        return f"{self.prefix}:holds"

    # -- the seam ---------------------------------------------------------- #
    @contextmanager
    def _transaction(self):
        with self._lock:                       # threads in THIS process
            if self._in_txn:
                yield                          # re-entrant; we hold the Redis lock
                return
            token = uuid.uuid4().hex
            try:
                acquired = self._acquire(token)
            except Exception as exc:           # noqa: BLE001 - any client failure
                yield from self._degraded(exc)
                return
            if not acquired:
                yield from self._degraded(
                    TimeoutError(
                        f"could not acquire {self._lock_key} within "
                        f"{self.lock_wait_seconds}s"
                    )
                )
                return
            self._in_txn = True
            try:
                self._sync_log()
                self._load_sidecar()
                yield
                self._save_sidecar()
            finally:
                self._in_txn = False
                self._release(token)

    def _acquire(self, token: str) -> bool:
        deadline = time.monotonic() + self.lock_wait_seconds
        delay = 0.005
        while True:
            if self.client.set(
                self._lock_key, token, nx=True, px=self.lock_ttl_ms
            ):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(delay)
            delay = min(delay * 2, 0.1)

    def _release(self, token: str) -> None:
        """Compare-and-delete: never delete a lock that is no longer ours.

        A TTL can expire while this node is still inside the transaction (a GC
        pause, a paused container). An unconditional delete would then remove the
        lock a DIFFERENT node has since taken, and two writers would proceed
        each believing it held it alone.
        """
        def _cad(pipe) -> None:
            current = pipe.get(self._lock_key)
            if current is None:
                return
            if isinstance(current, bytes):
                current = current.decode("utf-8", "replace")
            if current != token:
                return                          # expired under us; not ours to free
            pipe.multi()
            pipe.delete(self._lock_key)

        try:
            self.client.transaction(_cad, self._lock_key)
        except Exception:  # noqa: BLE001, S110 - see below
            # The lock TTLs out on its own, so failing to release it is a delay
            # and never a correctness problem. Raising here would replace a
            # completed transaction's result with a cleanup error, which is the
            # worst of both: the spend is booked and the caller is told it failed.
            pass

    def _degraded(self, exc: Exception):
        """Backend unreachable: apply the configured policy, and COUNT it."""
        self.unavailable_count += 1
        if self.on_unavailable == "allow":
            # Explicitly chosen: proceed on this node's view, which is a ceiling
            # per node rather than none at all. `_in_txn` is set for the same
            # reason as on the success path, `reserve` calls `spent`, which
            # opens its own transaction, and without it one refused action would
            # be reported as two backend outages.
            self._in_txn = True
            try:
                yield
            finally:
                self._in_txn = False
            return
        raise LedgerUnavailable(
            f"cannot reach the shared ledger at {self._lock_key}: "
            f"{type(exc).__name__}: {exc}"
        )

    # -- committed spend --------------------------------------------------- #
    def _sync_log(self) -> None:
        """Merge entries appended by other nodes since the last look.

        A LIST index replaces the file backend's byte offset. There is no torn
        write to guard against, `RPUSH` is atomic and an element is whole or
        absent, so the partial-line handling has no analogue here. A malformed
        element is skipped rather than aborting the sync, matching the file
        backend: under-counting is the direction that lets an attack through, so
        a skip is logged by its absence rather than by dropping the rest.
        """
        entries = self.client.lrange(self._log_key, self._offset, -1)
        if not entries:
            return
        for raw in entries:
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8", "replace")
            try:
                entry = LedgerEntry.from_dict(json.loads(raw))
            except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                continue
            key = (entry.principal, entry.budget_id)
            self._entries.append(entry)
            self._index.setdefault(key, []).append(entry)
            self._totals[key] = self._totals.get(key, Decimal(0)) + entry.amount
        self._offset += len(entries)

    def _append(self, entry: LedgerEntry) -> None:
        """Commit before acknowledging, then skip our own entry on the next sync."""
        PrincipalLedger._append(self, entry)
        self.client.rpush(self._log_key, json.dumps(entry.to_dict()))
        # `book` already merged this entry in memory, so advance past it rather
        # than counting it twice on the next sync.
        try:
            self._offset = int(self.client.llen(self._log_key))
        except Exception:                       # noqa: BLE001
            self._offset += 1

    # -- shared holds ------------------------------------------------------ #
    def _load_sidecar(self) -> None:
        try:
            blob = self.client.get(self._holds_key)
        except Exception:                       # noqa: BLE001
            return
        if not blob:
            return
        if isinstance(blob, bytes):
            blob = blob.decode("utf-8", "replace")
        try:
            raw = json.loads(blob)
        except json.JSONDecodeError:
            return
        holds: dict = {}
        for item in raw.get("holds", []):
            try:
                hold = Hold(
                    principal=item["principal"],
                    budget_id=item["budget_id"],
                    amount=Decimal(item["amount"]),
                    created_at=float(item["created_at"]),
                    hold_id=item["hold_id"],
                    ceiling=Decimal(item.get("ceiling", "0")),
                )
            except (KeyError, ValueError, ArithmeticError):
                continue
            holds.setdefault((hold.principal, hold.budget_id), []).append(hold)
        # The store is the ONLY source of truth for holds. Merging this node's
        # own `_holds` on top resurrects holds their owners already released
        # measured on the file backend as 5 phantom holds pinning 50 of a 100
        # ceiling. Nothing needs preserving: a hold created in this transaction
        # is written before the transaction ends, and `release` matches on
        # `hold_id` rather than object identity.
        self._holds = holds
        self._reserved = {
            k: sum((h.amount for h in v), Decimal(0)) for k, v in holds.items()
        }
        self._voided |= set(raw.get("voided", []))

    def _save_sidecar(self) -> None:
        payload = {
            "holds": [
                {
                    "principal": h.principal,
                    "budget_id": h.budget_id,
                    "amount": str(h.amount),
                    "created_at": h.created_at,
                    "hold_id": h.hold_id,
                    "ceiling": str(h.ceiling),
                }
                for group in self._holds.values()
                for h in group
            ],
            "voided": sorted(self._voided)[-4096:],
        }
        self.client.set(self._holds_key, json.dumps(payload))

    def release(self, hold: Hold | None) -> None:
        """Match by hold_id, not identity, see `SharedPrincipalLedger.release`.

        After a sync the list holds RECONSTRUCTED `Hold` objects for the same
        reservation, so the base class's `is` comparison fails and the headroom
        is never returned.
        """
        if hold is None:
            return
        with self._transaction():
            key = (hold.principal, hold.budget_id)
            holds = self._holds.get(key)
            if not holds:
                return
            for i, candidate in enumerate(holds):
                if candidate.hold_id == hold.hold_id:
                    holds.pop(i)
                    self._reserved[key] = self._reserved.get(key, Decimal(0)) - candidate.amount
                    if self._reserved[key] <= 0:
                        self._reserved.pop(key, None)
                    self._voided.add(hold.hold_id)
                    return

    def health(self) -> dict[str, Any]:
        base = super().health()
        base.update(
            {
                "backend": "redis",
                "cross_process": True,
                "cross_host": True,
                "unavailable": self.unavailable_count,
            }
        )
        return base


def redis_ledger_from_env(**kwargs: Any) -> RedisPrincipalLedger | None:
    """Build the backend from the environment, or ``None`` when unconfigured.

    Returning ``None`` rather than falling back to an in-memory ledger is
    deliberate: a silent downgrade from a shared ceiling to a per-process one is
    the failure this module exists to remove, and it would look like success.
    """
    url = os.environ.get(LEDGER_REDIS_URL_ENV, "").strip()
    if not url:
        return None
    try:
        import redis  # optional extra, imported only when configured
    except ImportError as exc:  # pragma: no cover - depends on the environment
        # Every other optional adapter names its extra here. This one did not,
        # so an operator who set the ledger URL got a bare ImportError and no
        # indication of which install fixes it.
        raise ImportError(
            "the shared principal ledger needs the redis client. Install with: "
            "pip install 'agentauth-capabilities[redis]'") from exc

    prefix = os.environ.get(LEDGER_REDIS_PREFIX_ENV, "").strip() or "agentauth:ledger"
    return RedisPrincipalLedger(
        client=redis.Redis.from_url(url), prefix=prefix, **kwargs
    )
