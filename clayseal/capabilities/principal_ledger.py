"""Principal-scoped budget ledger: aggregate limits that survive the session.

Every aggregate control in this library, and every one in the 2026 literature,
keys its ledger to the session. ``SessionValueBudget`` and ``SessionCallBudget``
are named for it, and each is documented as "one instance per session (the
instance *is* the session's ledger)".

That is a control the adversary resets at will. Structuring is *defined* as
splitting an amount so no single transaction crosses a threshold, and against a
session-scoped ledger the agent analogue needs no capability it did not already
have: open a second conversation. `benchmarks/structuring.py` measures the
cliff, and it arrives as soon as one fragment fits under the ceiling.

This module moves the ledger to where the authority actually lives. A mandate
grants authority to a principal; the ledger is keyed to that mandate and spans
every session it authorizes, over a rolling time window. A session budget is
then a *view* onto it: seeded with what the principal has already spent, and
writing its commitments back.

Three properties the design has to hold, because a persistent ledger has
failure modes a session one does not:

**Windows, not forever.** A ceiling with no window is a lifetime quota that
eventually blocks all legitimate work. Spend ages out of the window, so the
question the ledger answers is "how much in the last N hours", which is the
question every real financial control asks.

**Crash consistency.** A ledger that loses writes under-counts, and
under-counting is the failure that lets an attack through. Commits are appended
before they are acknowledged, and the in-memory total is derived from the log
rather than cached beside it.

**Explicit principal identity.** The key must be the mandate, not the session,
the conversation, or the process. Getting this wrong silently reintroduces the
bug, so the key is required rather than defaulted.
"""
from __future__ import annotations

import json
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

from clayseal.capabilities.decision_sinks import (
    make_private_parent,
    open_private_append,
)

# Spend older than the window no longer counts against the ceiling. A day is the
# usual reporting period for the controls this imitates; callers should set it
# from policy rather than relying on the default.
DEFAULT_WINDOW_SECONDS = 24 * 60 * 60


class LedgerUnavailable(RuntimeError):
    """The shared ledger could not be reached, so no ceiling could be checked.

    Its own exception type because the caller has to be able to tell it from
    every other failure. A raw `PermissionError` or `ConnectionError` escaping
    the authorization path is fail-closed only by accident: it takes the request
    down, it is indistinguishable from a bug, and nothing counts it. The whole
    point of a ceiling is that somebody notices when it stops being enforced.
    """


def principal_key(binding: Any) -> str:
    """Derive this ledger's key from an `AuthorityBinding`, without collisions.

    Do not pass ``binding.subject_id`` directly. It is the raw ``sub`` claim, and
    ``sub`` is unique only *within* an issuer, OIDC Core says so explicitly, and
    `benchmarks/stress_identity.py` confirms every adapter here behaves that way:
    ``sub="alice"`` from ``https://good.example`` and from ``https://evil.example``
    produce the same ``subject_id`` on all five.

    That is a live problem specifically *because* of this module. This ledger is
    the fix for the session-restart escape in `stress_aggregation.py`, so its key
    is the thing an attacker now has reason to attack, and in a deployment
    trusting more than one issuer an unqualified ``sub`` means two distinct
    principals share one ceiling. Either can exhaust the other's budget, and the
    spend attribution in the log is wrong for both.

    The issuer is therefore part of the key, length-prefixed rather than
    delimiter-joined. A plain ``f"{iss}|{sub}"`` is forgeable: ``sub`` is
    attacker-chosen at their own issuer, so ``sub="|https://good.example|alice"``
    spells another principal's key. Length prefixes make the encoding injective,
    so no pair of inputs can produce the same output.
    """
    issuer = str(getattr(binding, "issuer", "") or "")
    subject = str(getattr(binding, "subject_id", "") or "")
    if not subject:
        raise ValueError(
            "cannot key a principal ledger on a binding with no subject_id; "
            "an unidentified principal must not share a ceiling with anyone")
    return f"{len(issuer)}:{issuer}{len(subject)}:{subject}"


def principal_chain(binding: Any) -> tuple[str, ...]:
    """Every principal a delegate's spend must also count against.

    Delegation splitting is the escape this closes, and it was wide open:
    measured at **600 landed against a ceiling of 100** for a parent plus five
    sub-agents, because each sub-agent has its own ``sub`` and therefore its own
    `principal_key` and its own ceiling. The plan calls this axis "unclosed by
    construction, and where MCP deployments live", and a per-delegate ceiling is
    not a ceiling: an attacker who can spawn sub-agents mints headroom.

    Returned root-first and EXCLUDING the binding's own key, which the caller
    already has from `principal_key`. Chain entries are qualified with the same
    issuer, because a delegation chain is issued within one trust domain and an
    unqualified entry would collide across issuers exactly as a bare ``sub``
    does.
    """
    issuer = str(getattr(binding, "issuer", "") or "")
    out: list[str] = []
    for entry in getattr(binding, "delegation_chain", ()) or ():
        subject = str(entry or "")
        if subject:
            out.append(f"{len(issuer)}:{issuer}{len(subject)}:{subject}")
    return tuple(out)


@dataclass(frozen=True)
class Hold:
    """An outstanding reservation. Opaque on purpose: it is a capability.

    `release` used to take (principal, budget_id, amount) and subtract from a
    pool shared by every session of the principal, so any session could release
    an amount it never reserved and wipe every other session's hold. Holding a
    reference is now the only way to give one back.
    """

    principal: str
    budget_id: str
    amount: Decimal
    created_at: float
    #: Stable identity for settlement bookkeeping. Object identity is not
    #: enough: a released Hold can be collected and a new one allocated at the
    #: same address, so an `id()`-keyed set silently conflates two holds.
    hold_id: str = field(default_factory=lambda: uuid4().hex)
    #: The ceiling this hold was checked against, captured at reserve time. A
    #: late commit has to re-check, and the caller of `commit_hold` does not
    #: pass a ceiling: the authorize/act/commit split means it may not still
    #: have one in scope.
    ceiling: Decimal = Decimal(0)
    #: The object this reservation acts on, when the effect declares one. Held
    #: so that releasing gives the identity back and committing keeps it.
    identity: str = ""


@dataclass(frozen=True)
class LedgerEntry:
    principal: str
    budget_id: str
    amount: Decimal
    at: float
    session: str = ""
    idempotency_key: str = ""
    #: The object this spend acted on, when the effect declares one. Persisted
    #: because once-per-object has to survive a PROCESS boundary and not only a
    #: session one: a stateless deployment is many processes, and an identity
    #: kept only in memory let a second process pay the same invoice again. The
    #: ceiling survived that boundary and the duplicate check did not, which is
    #: the more specific half of the same escape.
    identity: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal": self.principal, "budget_id": self.budget_id,
            "amount": str(self.amount), "at": self.at,
            "session": self.session, "idempotency_key": self.idempotency_key,
            "identity": self.identity,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> LedgerEntry:
        return cls(
            principal=d["principal"], budget_id=d["budget_id"],
            amount=Decimal(d["amount"]), at=float(d["at"]),
            session=d.get("session", ""), idempotency_key=d.get("idempotency_key", ""),
            identity=d.get("identity", ""),
        )


@dataclass
class PrincipalLedger:
    """Append-only spend log keyed by principal, queried over a time window.

    Not a cache with a total beside it: `spent` recomputes from the entries in
    window every time it is asked. That is slower and it is the reason a lost or
    duplicated write cannot silently corrupt a ceiling.
    """

    window_seconds: int = DEFAULT_WINDOW_SECONDS
    path: Path | None = None          # None keeps the ledger in memory only
    _entries: list[LedgerEntry] = field(default_factory=list)
    # Index by (principal, budget_id). A flat scan cost 4.75 ms per read at
    # 20,000 entries, which is 100x the entire per-action enforcement stack and
    # would have made the ledger the slowest thing in the request path.
    _index: dict[tuple[str, str], list[LedgerEntry]] = field(default_factory=dict)
    # Reserved-but-not-committed spend, so a check and its commit are atomic
    # with respect to other sessions. Without this two concurrent sessions both
    # pass `would_allow` before either commits.
    _reserved: dict[tuple[str, str], Decimal] = field(default_factory=dict)
    # The holds behind that total, so a release can be scoped to one of them.
    _holds: dict[tuple[str, str], list[Hold]] = field(default_factory=dict)
    # Running in-window total per key. Indexing alone did not help: 20,000
    # entries for one busy principal is one bucket, so reads stayed at 3.6 ms.
    # This is a cache, which the original design deliberately avoided because a
    # total that drifts from its log silently raises a ceiling. `verify_totals`
    # is the answer to that: the invariant is checkable on demand and is checked
    # in the tests, so the speed does not cost auditability.
    _totals: dict[tuple[str, str], Decimal] = field(default_factory=dict)
    # Holds that have already been booked, by hold_id. An expired hold is
    # SETTLED rather than dropped (see `_expire_holds`), and a later
    # `commit_hold` for it must return the existing entry instead of booking a
    # second one.
    _settled: dict[str, LedgerEntry] = field(default_factory=dict)
    # Holds whose TTL passed. Their headroom is released, so a late commit is
    # booked against a ceiling that has since been re-let. It is still booked
    # the effect happened, but it is recorded as a breach rather than absorbed.
    _voided: set[str] = field(default_factory=set)
    #: (principal, budget_id) -> object identities already committed, and those
    #: currently held by an open reservation. Once-per-object was a
    #: `SessionValueBudget` rule and therefore reset with the session, which is
    #: the same escape the spend ledger moved here to close: paying the same
    #: invoice once per session is not paying it once.
    _identities: dict[tuple[str, str], set[str]] = field(default_factory=dict)
    _held_identities: dict[tuple[str, str], set[str]] = field(default_factory=dict)
    _late_breaches: list[LedgerEntry] = field(default_factory=list)
    _lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)
    _tail_checked: bool = False

    @contextmanager
    def _transaction(self):
        """The atomicity boundary for every read-modify-write below.

        `threading.RLock` is process-local, and that is the whole limitation of
        this class: four OS processes sharing one ledger file each loaded it,
        each saw nothing spent, each reserved, each committed. **400 landed
        against a ceiling of 100.** It is the same check-then-act race `reserve`
        already fixes for threads, one layer out, and it matters because every
        real deployment is horizontally scaled, a second gunicorn worker or k8s
        replica reintroduces exactly the session-restart escape this module
        exists to close.

        Subclasses widen this to a lock the operating system or a database
        enforces. `SharedPrincipalLedger` is the POSIX one; the same seam is
        where a Redis or Postgres backend goes, and `RedisUsedTokenStore` is the
        precedent, the replay layer has been multi-instance for a while and the
        ledger carrying the headline claim had not caught up.
        """
        with self._lock:
            yield

    def __post_init__(self) -> None:
        if self.path is not None and self.path.exists():
            self._load()

    # -- persistence --------------------------------------------------------
    def _load(self) -> None:
        entries = []
        for line in self.path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(LedgerEntry.from_dict(json.loads(line)))
            except (json.JSONDecodeError, KeyError, ValueError):
                # A torn final line from an interrupted append. Skipping it is
                # correct: the entry was never acknowledged, so no caller was
                # told the spend was booked.
                continue
        self._entries = entries
        for e in entries:
            key = (e.principal, e.budget_id)
            self._index.setdefault(key, []).append(e)
            self._totals[key] = self._totals.get(key, Decimal(0)) + e.amount
            if e.identity:
                self._identities.setdefault(key, set()).add(e.identity)

    def _repair_torn_tail(self) -> None:
        """Drop a partial final record before appending after it.

        A crash mid-append leaves bytes with no trailing newline. The next
        append then concatenates onto them, and the merged line parses as
        neither record, so BOTH are lost on the next load: an acknowledged
        booking of 500 vanished and the ledger reloaded at 100 instead of 600.

        Under-counting is the failure direction that matters. An over-counted
        ledger refuses work; an under-counted one raises a ceiling that an
        operator believes is in force.

        The torn record itself is correctly discarded, because it was never
        acknowledged to any caller. What must not happen is it taking the next
        one with it.
        """
        if self.path is None or not self.path.exists():
            return
        try:
            size = self.path.stat().st_size
            if size == 0:
                return
            with self.path.open("rb+") as fh:
                fh.seek(-1, 2)
                if fh.read(1) == b"\n":
                    return
                data = self.path.read_bytes()
                cut = data.rfind(b"\n")
                fh.truncate(cut + 1 if cut >= 0 else 0)
        except OSError:
            # A ledger that cannot repair itself must not take the session down;
            # the load path already skips unparseable lines.
            return

    def _append(self, entry: LedgerEntry) -> None:
        if self.path is None:
            return
        make_private_parent(self.path)
        if not self._tail_checked:
            self._repair_torn_tail()
            self._tail_checked = True
        with open_private_append(self.path) as fh:
            fh.write(json.dumps(entry.to_dict()) + "\n")
            fh.flush()
            # Acknowledgement has to mean durable. Without this the caller is
            # told the spend is booked while it sits in the OS page cache, and a
            # power loss under-counts the ceiling.
            os.fsync(fh.fileno())

    # -- queries ------------------------------------------------------------
    def _prune(self, key: tuple[str, str], cutoff: float) -> list[LedgerEntry]:
        """Drop out-of-window entries for one key. Bounds both memory and read
        cost by the window rather than by the lifetime of the deployment."""
        bucket = self._index.get(key)
        if bucket is None:
            return []
        if bucket and bucket[0].at < cutoff:
            kept = [e for e in bucket if e.at >= cutoff]
            dropped = sum((e.amount for e in bucket if e.at < cutoff), Decimal(0))
            self._index[key] = kept
            self._totals[key] = self._totals.get(key, Decimal(0)) - dropped
            bucket = kept
        return bucket

    def spent(self, principal: str, budget_id: str, *, now: float | None = None) -> Decimal:
        """Total booked for this principal and budget inside the window."""
        cutoff = (time.time() if now is None else now) - self.window_seconds
        key = (principal, budget_id)
        with self._transaction():
            self._prune(key, cutoff)
            return self._totals.get(key, Decimal(0))

    def verify_totals(self) -> bool:
        """Recompute every total from the entries and compare.

        The running totals are an optimisation, and an optimisation that can
        drift from its log is how a ceiling silently rises. This makes the
        invariant checkable rather than assumed.
        """
        with self._transaction():
            for key, bucket in self._index.items():
                if self._totals.get(key, Decimal(0)) != sum(
                        (e.amount for e in bucket), Decimal(0)):
                    return False
            return True

    def entries_in_window(self, principal: str, budget_id: str,
                          *, now: float | None = None) -> list[LedgerEntry]:
        cutoff = (time.time() if now is None else now) - self.window_seconds
        with self._transaction():
            return [e for e in self._prune((principal, budget_id), cutoff) if e.at >= cutoff]

    # -- mutation -----------------------------------------------------------
    def book(self, principal: str, budget_id: str, amount: Decimal, *,
             session: str = "", idempotency_key: str = "",
             now: float | None = None, identity: str = "") -> LedgerEntry:
        """Record spend. Idempotent on ``idempotency_key`` within a session.

        Idempotency exists so a retried tool call does not debit twice. It is
        also a hole, and it was an exploitable one: the key used to be read from
        the agent's own tool arguments, so an injected agent could reuse one key
        and move eight payments while the ledger booked one. Measured at 40,000
        moved against a 10,000 ceiling.

        Two changes close it. The key is now scoped to the **session**, so
        reusing it in a different session books normally, which is exactly the
        cross-session case the ledger exists to catch. And the **amount must
        match**, so a small authorized payment cannot launder a large one under
        the same key. A caller that wants true idempotency must supply the key
        from trusted context rather than from arguments the agent controls.
        """
        at = time.time() if now is None else now
        entry = LedgerEntry(principal, budget_id, amount, at, session,
                            idempotency_key, identity)
        key = (principal, budget_id)
        # A control must not trust its own callers. `_amount` already rejects
        # non-positive values at the boundary, and this is the second gate: a
        # negative booking drives the window total down, so `spent`,
        # `remaining` and `would_exceed` all report headroom that does not
        # exist while `verify_totals` still returns True, because the cache and
        # the log agree on the wrong number. 180,000 was moved against a 10,000
        # ceiling this way. Refunds, if they are ever needed, need an explicit
        # entry point that a tracked tool argument cannot reach.
        if not amount.is_finite() or amount <= 0:
            raise ValueError(
                f"ledger amounts must be finite and positive, got {amount!r}")
        with self._transaction():
            if idempotency_key:
                cutoff = at - self.window_seconds
                for existing in self._prune(key, cutoff):
                    if (existing.idempotency_key == idempotency_key
                            and existing.session == session
                            and existing.amount == amount
                            and existing.at >= cutoff):
                        return existing
            self._append(entry)
            self._entries.append(entry)
            self._index.setdefault(key, []).append(entry)
            self._totals[key] = self._totals.get(key, Decimal(0)) + amount
        return entry

    # How long an unreleased hold survives. A reservation that never expires is
    # a denial-of-service: an agent that authorizes and then dies (a timeout, a
    # crash, an exception on the tool call) shrinks the principal's ceiling
    # permanently, and enough abandoned holds take it to zero. The TTL should be
    # of the order of the tool timeout.
    reservation_ttl_seconds: float = 300.0

    def identity_seen(self, principal: str, budget_id: str, identity: str) -> bool:
        """Has this object already been acted on, committed or held right now?"""
        key = (principal, budget_id)
        return (identity in self._identities.get(key, ())
                or identity in self._held_identities.get(key, ()))

    def reserve(self, principal: str, budget_id: str, amount: Decimal,
                ceiling: Decimal, *, now: float | None = None,
                identity: str | None = None) -> Hold | None:
        """Atomically check the ceiling and hold the amount against it.

        `would_allow` followed by `commit` is a check-then-act race: eight
        concurrent sessions each passed the check and each committed, moving
        40,000 against a 10,000 ceiling. Holding the reservation under the same
        lock as the check is what makes the ceiling a ceiling.

        Returns an opaque `Hold` rather than a bool, and `release` takes that
        Hold rather than an amount. The amount-keyed form was a cross-session
        weapon: `release(principal, budget, 10000)` subtracted from the single
        pool shared by every session of that principal, so any session could
        wipe every other session's hold and then book above the ceiling. A Hold
        can only be released once, and only by whoever holds it.
        """
        if not amount.is_finite() or amount <= 0:
            raise ValueError(
                f"reservation amounts must be finite and positive, got {amount!r}")
        at = time.time() if now is None else now
        with self._transaction():
            key = (principal, budget_id)
            self._expire_holds(key, at)
            # Once-per-object, checked under the SAME lock as the ceiling. A
            # ceiling answers "is the total under the limit" and answers it
            # correctly while the same invoice is paid twice.
            if identity is not None and (
                    identity in self._identities.get(key, ())
                    or identity in self._held_identities.get(key, ())):
                return None
            held = sum((h.amount for h in self._holds.get(key, ())), Decimal(0))
            projected = self.spent(principal, budget_id, now=now) + held + amount
            if projected > ceiling:
                return None
            hold = Hold(principal=principal, budget_id=budget_id,
                        amount=amount, created_at=at, ceiling=ceiling,
                        identity=identity or "")
            self._holds.setdefault(key, []).append(hold)
            self._reserved[key] = held + amount
            if identity is not None:
                self._held_identities.setdefault(key, set()).add(identity)
            return hold

    def _expire_holds(self, key: tuple[str, str], at: float) -> None:
        """Void expired holds: free the headroom, but mark them.

        Dropping them silently was a measured escape. `commit_hold` books from
        the Hold and cannot re-check the ceiling at the point it is called
        (authorize -> act -> commit means the effect has already landed), so a
        forgotten hold freed the headroom while staying perfectly committable:

            reserve 100 of a 100 ceiling, wait out the 300s TTL, reserve 100
            again (the first hold has evaporated, so it fits), then commit both.
            **200 booked against a ceiling of 100.** No clock control required,
            only patience.

        Two fixes were wrong before this one. *Refusing* the late commit
        under-counts, and this module's own premise is that "under-counting is
        the failure that lets an attack through". *Settling* the hold as spend
        on expiry never under-counts, but it re-opens exactly the denial of
        service the TTL was added for, and
        `test_an_abandoned_hold_expires_instead_of_shrinking_the_ceiling_forever`
        pins that.

        So the hold is voided, headroom returns, DoS stays fixed, and its id
        is remembered. `commit_hold` re-checks against the ceiling captured on
        the Hold and books either way, recording a breach when it no longer
        fits. The escape becomes visible instead of silent, which is the same
        standard `aggregation_residual.md` holds the mandate escapes to.
        """
        holds = self._holds.get(key)
        if not holds:
            return
        cutoff = at - self.reservation_ttl_seconds
        live = [h for h in holds if h.created_at >= cutoff]
        if len(live) == len(holds):
            return
        for hold in holds:
            if hold.created_at < cutoff:
                self._voided.add(hold.hold_id)
                # The identity goes back with the headroom, and for the same
                # reason: an abandoned hold must not shrink the ceiling forever,
                # and it must not put one object out of reach forever either. A
                # voided hold that is later committed re-adds the identity in
                # `commit_hold`, so the object cannot be acted on twice.
                if hold.identity:
                    self._held_identities.get(key, set()).discard(hold.identity)
        self._holds[key] = live
        self._reserved[key] = sum((h.amount for h in live), Decimal(0))

    def release(self, hold: Hold | None) -> None:
        """Give back a reservation whose action was refused downstream.

        Idempotent, and scoped to the one hold. Releasing twice, or releasing a
        hold that already expired, does nothing.
        """
        if hold is None:
            return
        with self._transaction():
            key = (hold.principal, hold.budget_id)
            holds = self._holds.get(key)
            if not holds:
                return
            for i, existing in enumerate(holds):
                if existing is hold:
                    holds.pop(i)
                    break
            else:
                return
            self._reserved[key] = sum((h.amount for h in holds), Decimal(0))
            # The object goes back on the shelf. A refused action did not act on
            # it, so holding its identity forever would make one denial a
            # permanent one.
            if hold.identity:
                self._held_identities.get(key, set()).discard(hold.identity)

    def commit_hold(self, hold: Hold | None, *, session: str = "",
                    idempotency_key: str = "", now: float | None = None):
        """Book exactly what was reserved, then drop the hold.

        The amount comes from the Hold rather than from the caller, so a
        reservation for 10 cannot be committed as 10,000.
        """
        if hold is None:
            return None
        with self._transaction():
            settled = self._settled.get(hold.hold_id)
            if settled is not None:
                # Already booked when it expired. Booking again would double
                # count, which is the safe direction and still wrong.
                self.release(hold)
                return settled
            breached = False
            if hold.hold_id in self._voided:
                # Its headroom was re-let when the TTL passed, so the ceiling
                # this books against is not the one it was checked against.
                # Book anyway (the effect landed; refusing to record it
                # under-counts) and record the breach.
                # Outstanding holds must be in the projection. They are the
                # reservations that were granted USING the headroom this hold
                # gave back when it was voided, so leaving them out is how the
                # first version of this check missed its own escape: committing
                # the voided hold looked like 100 against a ceiling of 100,
                # while a live hold for another 100 sat beside it.
                key = (hold.principal, hold.budget_id)
                outstanding = sum(
                    (h.amount for h in self._holds.get(key, ())
                     if h.hold_id != hold.hold_id), Decimal(0))
                projected = (self.spent(hold.principal, hold.budget_id, now=now)
                             + outstanding + hold.amount)
                breached = hold.ceiling > 0 and projected > hold.ceiling
            entry = self.book(hold.principal, hold.budget_id, hold.amount,
                              session=session or ("late-commit" if breached else ""),
                              idempotency_key=idempotency_key, now=now,
                              identity=hold.identity)
            self._settled[hold.hold_id] = entry
            if breached:
                self._late_breaches.append(entry)
            # Committed, so the identity moves from held to permanent BEFORE the
            # release below gives the held one back. `identity_seen` reads both,
            # so the object stays spent either way and the order only decides
            # which set holds it.
            if hold.identity:
                self._identities.setdefault(
                    (hold.principal, hold.budget_id), set()).add(hold.identity)
            self.release(hold)
            return entry

    def health(self) -> dict[str, Any]:
        """One snapshot an operator can alert on.

        Two fields here mean the ceiling stopped being enforced, and before this
        they were recorded and surfaced nowhere:

        ``late_breaches``    a commit landed after its hold was voided and no
                             longer fit. The spend IS booked and the log IS
                             correct; what happened is that the check did not
                             hold for it. Non-zero needs reconciling the same
                             day rather than being discovered a window later.
        ``unavailable``      transactions that could not reach the shared
                             backend. Whatever the configured policy, the
                             ceiling went unchecked for that many actions.

        ``totals_verified`` is the integrity invariant: the cached per-key totals
        recomputed from the log and compared. False means the fast path has
        drifted from the record, which silently raises a ceiling, and it is the
        field here that should page someone.

        Deliberately a plain dict of scalars rather than a metrics-library call.
        Whatever the deployment scrapes, it can scrape this.
        """
        with self._transaction():
            breaches = self.late_breaches()
            return {
                "entries": len(self._entries),
                "tracked_keys": len(self._index),
                "outstanding_holds": sum(len(v) for v in self._holds.values()),
                "late_breaches": len(breaches),
                "late_breach_value": str(sum((e.amount for e in breaches),
                                             Decimal(0))),
                "unavailable": int(getattr(self, "unavailable_count", 0)),
                "totals_verified": self.verify_totals(),
                "window_seconds": self.window_seconds,
                "reservation_ttl_seconds": self.reservation_ttl_seconds,
                "cross_process": type(self) is not PrincipalLedger,
            }

    def late_breaches(self) -> list[LedgerEntry]:
        """Commits that landed after their hold was voided and no longer fit.

        Non-empty means a ceiling was exceeded. The spend is booked and the log
        is correct; what this reports is that the CHECK did not hold for it, so
        an operator can reconcile rather than discover it a window later.
        """
        return list(self._late_breaches)

    def would_exceed(self, principal: str, budget_id: str, amount: Decimal,
                     ceiling: Decimal, *, now: float | None = None) -> bool:
        return self.spent(principal, budget_id, now=now) + amount > ceiling

    def remaining(self, principal: str, budget_id: str, ceiling: Decimal,
                  *, now: float | None = None) -> Decimal:
        return max(Decimal(0), ceiling - self.spent(principal, budget_id, now=now))


@dataclass(frozen=True)
class StructuringSignal:
    """Evidence that spend is being shaped by a limit rather than by the work.

    Advisory, never a blocker. Every statistical tier in this system escalates
    rather than denies, because the base rate of legitimate splitting is high:
    invoices really do arrive in batches and payroll really is uniform.
    """

    fragments: int
    total: Decimal
    ceiling: Decimal
    just_under: int          # entries deliberately parked below the limit
    uniformity: float        # 1.0 means every fragment identical
    effective_fragments: float = 0.0   # inverse Herfindahl: equal parts equivalent
    reasons: tuple[str, ...] = ()

    @property
    def suspicious(self) -> bool:
        return bool(self.reasons)

    @property
    def utilisation(self) -> float:
        return float(self.total / self.ceiling) if self.ceiling else 0.0

    def summary(self) -> dict[str, Any]:
        return {
            "fragments": self.fragments, "total": str(self.total),
            "ceiling": str(self.ceiling), "just_under": self.just_under,
            "uniformity": round(self.uniformity, 3),
            "utilisation": round(self.utilisation, 3),
            "suspicious": self.suspicious, "reasons": list(self.reasons),
        }


def structuring_signal(
    ledger: PrincipalLedger,
    principal: str,
    budget_id: str,
    ceiling: Decimal,
    *,
    now: float | None = None,
    just_under_ratio: float = 0.8,
    min_fragments: int = 4,
    uniformity_threshold: float = 0.95,
    utilisation_threshold: float = 0.85,
    # Effective equal-fragment count, from the inverse Herfindahl index. Two is
    # the floor at which "this was divided" is meaningful: a lone payment scores
    # exactly 1 and cannot be a split.
    min_effective_fragments: float = 2.0,
) -> StructuringSignal:
    """Distributional test for spend shaped by a ceiling.

    The existing AML analytic looks for amounts just below hard-coded round
    numbers, which misses the case that matters here: an attacker structures
    against *the ceiling actually in force*, not against 10,000 because it is a
    round number. Four payments of 2,600 under a 10,000 limit trip nothing in a
    round-number test and are the whole attack.

    Two signatures, deliberately different in kind so they fail independently:

    **Just-under parking.** Repeated amounts sitting in the top band below the
    limit is the classic signature, and it is what a naive structuring agent
    produces because it maximises throughput per transaction.

    **Fragmentation at high utilisation.** Many payments, none individually
    close to the limit, together consuming nearly all of it. This is the
    signature that survives an attacker jittering the amounts, which defeats the
    uniformity test below while moving exactly the same money.

    **Uniformity at high utilisation.** An amount divided into equal parts is
    the signature of a split rather than of work arriving. Real invoice runs
    vary; a divided total does not. Uniformity alone is not evidence, since
    payroll is uniform too, so it only counts when the fragments also consume
    most of the ceiling, which is what makes it look like a limit was the
    binding constraint rather than the business.
    """
    entries = ledger.entries_in_window(principal, budget_id, now=now)
    amounts = [e.amount for e in entries]
    total = sum(amounts, Decimal(0))
    if not amounts or ceiling <= 0:
        return StructuringSignal(len(amounts), total, ceiling, 0, 0.0)

    just_under = sum(
        1 for a in amounts if Decimal(str(just_under_ratio)) * ceiling <= a < ceiling
    )

    # Uniformity: 1 minus the spread relative to the mean, floored at zero. A
    # single fragment is trivially uniform and must not count as evidence.
    mean = total / len(amounts)
    if len(amounts) > 1 and mean > 0:
        spread = (max(amounts) - min(amounts)) / mean
        uniformity = max(0.0, 1.0 - float(spread))
    else:
        uniformity = 0.0

    utilisation = float(total / ceiling)
    reasons: list[str] = []
    if just_under >= min_fragments:
        reasons.append(
            f"{just_under} payments parked between {just_under_ratio:.0%} of the "
            f"{ceiling} ceiling and the ceiling itself"
        )
    if (len(amounts) >= min_fragments
            and uniformity >= uniformity_threshold
            and utilisation >= utilisation_threshold):
        reasons.append(
            f"{len(amounts)} near-identical payments consuming {utilisation:.0%} of "
            f"the {ceiling} ceiling, the shape of a divided total rather than "
            "of work arriving"
        )

    # Concentration, which does not depend on the amounts resembling each other
    # and has no cliff in it.
    #
    # Two earlier versions of this test were beaten. Uniformity alone fell to
    # 10% jitter while the same money moved. Replacing it with "many payments,
    # none individually large" introduced a threshold on the LARGEST fragment,
    # and that threshold was itself a blind spot: one payment anywhere between
    # 50% and 80% of the ceiling defeated the fragmentation gate at every
    # fragment count while sitting below the just-under band, so four of five
    # structuring patterns went unflagged.
    #
    # The measure here is the inverse Herfindahl index: the number of EQUAL
    # fragments that would produce the same concentration. It moves smoothly, so
    # there is no amount an attacker can pick to fall off the far side of it.
    # One payment of 6,000 plus four of 1,000 has an effective count of 2.5, and
    # a single payment has an effective count of exactly 1, which is why a lone
    # large payment cannot be structuring.
    shares = [float(a / total) for a in amounts] if total > 0 else []
    hhi = sum(x * x for x in shares)
    effective = (1.0 / hhi) if hhi > 0 else 0.0
    if (effective >= min_effective_fragments
            and utilisation >= utilisation_threshold):
        reasons.append(
            f"{len(amounts)} payments with an effective concentration of "
            f"{effective:.1f} equal parts consuming {utilisation:.0%} of the "
            f"{ceiling} ceiling, the shape of a total divided to fit rather "
            "than of work arriving"
        )

    return StructuringSignal(len(amounts), total, ceiling, just_under,
                             uniformity, effective, tuple(reasons))


@dataclass
class PrincipalBudgetView:
    """A session's view of a principal-scoped ceiling.

    Deliberately thin. The session does not hold a ledger of its own, so there
    is nothing to reset when the session ends and nothing to reconcile when two
    sessions run at once: both read and write the same log.
    """

    ledger: PrincipalLedger
    principal: str
    ceilings: dict[str, Decimal] = field(default_factory=dict)
    tracked: dict[str, tuple[str, str]] = field(default_factory=dict)
    session: str = ""
    #: Ancestor principal keys, from `principal_chain`. A delegate's spend is
    #: reserved and booked against every one of them as well as its own, so the
    #: parent's ceiling bounds the aggregate of everything it delegated to.
    #: Empty for a non-delegated principal, which is the previous behaviour.
    chain: tuple[str, ...] = ()

    def _principals(self) -> tuple[str, ...]:
        return (self.principal, *self.chain)

    def _reserve_group(self, budget_id: str, amount: Decimal,
                       ceiling: Decimal, now: float | None,
                       identity: str | None = None):
        """Reserve against self and every ancestor, all-or-nothing.

        A partial reservation would leave an ancestor's headroom consumed for a
        delegate action that never happened, which is the denial of service the
        hold TTL exists to prevent, arriving by a different route.
        """
        taken = []
        for who in self._principals():
            hold = self.ledger.reserve(who, budget_id, amount, ceiling, now=now,
                                       identity=identity)
            if hold is None:
                for done in taken:
                    self.ledger.release(done)
                return None
            taken.append(hold)
        return taken

    def reserve(self, tool_name: str, args: dict[str, Any]):
        """The broker's entry point, against a ledger the session does not own.

        Mirrors `SessionValueBudget.reserve` and deliberately does not
        re-implement it: the amount is read by the shared `parse_amount`, so
        there is one answer to "how much does this call move", and the
        once-per-object check happens inside `PrincipalLedger.reserve` under the
        same lock as the ceiling, because a ceiling answers "is the total under
        the limit" and answers it correctly while the same invoice is paid twice.

        The tri-state that `parse_amount` returns is preserved exactly. An
        untracked call is allowed; a TRACKED call whose amount cannot be read is
        refused, because reading that as untracked is the fail-open this
        library already had once.
        """
        from clayseal.capabilities.value_budget import parse_amount

        config = getattr(self, "config", None)
        if config is None:
            return PrincipalReservation(True, "ok_untracked")
        parsed = parse_amount(config, tool_name, args)
        if parsed is None:
            return PrincipalReservation(True, "ok_untracked")
        if getattr(config, "tightened", False):
            return PrincipalReservation(False, "value_budget_disabled_tightened")
        budget_id, amount = parsed
        if amount is None:
            return PrincipalReservation(False, "value_budget_unparseable_amount")
        if amount < 0:
            return PrincipalReservation(False, "value_budget_negative_amount")
        ceiling = config.ceiling_for(budget_id)
        if ceiling is None:
            return PrincipalReservation(True, "ok_uncapped")
        spec = config.spec_for(tool_name)
        identity = spec.identity_of(args) if spec is not None else None
        if identity is not None and any(
                self.ledger.identity_seen(who, budget_id, identity)
                for who in self._principals()):
            return PrincipalReservation(False, "value_budget_duplicate_effect")
        raw_key = args.get("_idempotency_key")
        idem = raw_key.strip() if isinstance(raw_key, str) and raw_key.strip() else None
        holds = self._reserve_group(budget_id, amount, ceiling, None,
                                    identity=identity)
        if holds is None:
            return PrincipalReservation(False, "value_budget_exceeded")
        return PrincipalReservation(True, "ok", _view=self, _holds=holds,
                                    _idempotency_key=idem)

    def _amount(self, tool_name: str, args: dict[str, Any]) -> tuple[str, Decimal] | None:
        spec = self.tracked.get(tool_name)
        if spec is None:
            return None
        arg_name, budget_id = spec
        raw = args.get(arg_name)
        if not isinstance(raw, (int, float, str, Decimal)) or isinstance(raw, bool):
            return None
        try:
            amount = Decimal(str(raw))
        except (ValueError, ArithmeticError):
            return None
        # This value comes from the agent's own tool arguments. A negative one
        # is a global disable switch for the principal's ceiling: `reserve` adds
        # it straight into the shared hold, which is keyed by principal and
        # budget rather than by session, so a single call of -1,000,000,000
        # lifted the ceiling for every concurrent and subsequent session of that
        # principal. Measured at 499,950 moved against a ceiling of 10,000.
        # NaN and the infinities poison the same arithmetic without the sign.
        if not amount.is_finite() or amount <= 0:
            return None
        return budget_id, amount

    def would_allow(self, tool_name: str, args: dict[str, Any],
                    *, now: float | None = None) -> tuple[bool, str]:
        """Read-only projection. NOT SAFE FOR ENFORCEMENT.

        This reports whether the spend would fit right now and holds nothing.
        Using it as a gate is a check-then-act race: eight concurrent sessions
        each passed it and each committed, moving 40,000 against a 10,000
        ceiling. Use `authorize`, which checks and holds under one lock.

        Retained for monitoring and for reporting remaining headroom, which is
        the only thing it is correct for.
        """
        parsed = self._amount(tool_name, args)
        if parsed is None:
            return True, "not tracked by a principal budget"
        budget_id, amount = parsed
        ceiling = self.ceilings.get(budget_id)
        if ceiling is None:
            return True, f"no principal ceiling for {budget_id}"
        already = self.ledger.spent(self.principal, budget_id, now=now)
        if already + amount > ceiling:
            window_h = self.ledger.window_seconds / 3600
            return False, (
                f"principal budget {budget_id}: {already + amount} would exceed "
                f"{ceiling} over {window_h:.0f}h for {self.principal} "
                f"({already} already spent across prior sessions)"
            )
        return True, f"within principal budget {budget_id}"

    # Holds this session is carrying between authorize and commit, keyed by the
    # budget and amount they were taken for.
    _holds: dict = field(default_factory=dict)

    def release(self, tool_name: str, args: dict[str, Any]) -> None:
        """Give back a hold for an action a later rung refused.

        Without this an authorize that never commits leaves the hold to expire
        on the TTL, which is correct but slow: the principal's ceiling stays
        shrunk for the whole window in the meantime.
        """
        parsed = self._amount(tool_name, args)
        if parsed is None:
            return
        budget_id, _amount = parsed
        group = self._holds.get(budget_id)
        for hold in (group.pop(0) if group else ()):
            self.ledger.release(hold)

    def commit(self, tool_name: str, args: dict[str, Any],
               *, now: float | None = None) -> None:
        """Book the reservation `authorize` took. Fails closed without one.

        The amount comes from the HOLD and never from `args`. Re-deriving it
        from the caller was the whole defect: `commit` looked the hold up by
        (budget_id, str(amount)), missed whenever the committed amount differed
        from the authorized one, and fell through to a `book()` that takes no
        ceiling and re-checks nothing.

        Two measured consequences. Authorize 10 and commit 10,000, and 10,000 was
        booked against a ceiling of 1,000 with the 10 hold still outstanding. And
        two sessions each authorized 900 against a 1,000 ceiling, the second
        correctly refused, yet both committed and the ledger recorded 1,800 with
        `verify_totals()` still True, because the cache and the log agreed on a
        number the ceiling never approved.

        A caller with no reservation is refused rather than booked. Booking
        unreserved spend is what made the reservation decorative, and any path
        that genuinely needs it should say so by calling `PrincipalLedger.book`
        directly, where the absence of a ceiling argument is visible.
        """
        parsed = self._amount(tool_name, args)
        if parsed is None:
            return
        budget_id, amount = parsed
        held = self._holds.get(budget_id)
        if not held:
            # No reservation: the `would_allow` + `commit` flow. Keep it, but
            # CHECK THE CEILING here rather than booking blind. The defect was
            # never that this path existed, it was that it called `book()`,
            # which takes no ceiling and re-checks nothing, so two sessions each
            # refused at 900 against a 1,000 ceiling both committed and the
            # ledger recorded 1,800.
            ceiling = self.ceilings.get(budget_id)
            if ceiling is None:
                self.ledger.book(
                    self.principal, budget_id, amount, session=self.session,
                    idempotency_key=str(args.get("_idempotency_key") or ""), now=now)
                return
            late = self._reserve_group(budget_id, amount, ceiling, now)
            if late is None:
                raise ValueError(
                    f"commit for {budget_id!r} would exceed the {ceiling} ceiling "
                    f"for {self.principal}; authorize() first"
                )
            for hold in late:
                self.ledger.commit_hold(
                    hold, session=self.session,
                    idempotency_key=str(args.get("_idempotency_key") or ""),
                    now=now)
            return
        group = held.pop(0)
        # The reservation is the authority, so the RESERVED amount is booked and
        # the caller's number is ignored. Re-deriving it from args was the
        # bypass: authorize 10, commit 10,000, and 10,000 was booked.
        for hold in group:
            self.ledger.commit_hold(
                hold, session=self.session,
                idempotency_key=str(args.get("_idempotency_key") or ""), now=now)

    def authorize(self, tool_name: str, args: dict[str, Any],
                  *, now: float | None = None) -> tuple[bool, str]:
        """Atomic check-and-hold. Prefer this over `would_allow` on any path
        where more than one session can be live at once, which is every real
        deployment."""
        parsed = self._amount(tool_name, args)
        if parsed is None:
            return True, "not tracked by a principal budget"
        budget_id, amount = parsed
        ceiling = self.ceilings.get(budget_id)
        if ceiling is None:
            return True, f"no principal ceiling for {budget_id}"
        try:
            hold = self._reserve_group(budget_id, amount, ceiling, now)
        except LedgerUnavailable as exc:
            # Fail closed, and say why. Returning a bare False here would make
            # "over ceiling" and "no ceiling was checked" the same event in
            # every log and dashboard downstream.
            return False, f"principal budget {budget_id}: {exc}"
        if hold is not None:
            # Queued per budget, NOT keyed on the amount. Keying on
            # (budget_id, str(amount)) meant `commit` re-derived the key from
            # the caller's own arguments, so a commit whose amount differed from
            # the authorized one missed the hold entirely and fell through to an
            # unchecked book(). Authorize 10, commit 10,000, and 10,000 was
            # booked against a ceiling of 1,000 with the hold still outstanding.
            self._holds.setdefault(budget_id, []).append(hold)
            return True, f"within principal budget {budget_id}"
        already = self.ledger.spent(self.principal, budget_id, now=now)
        window_h = self.ledger.window_seconds / 3600
        return False, (
            f"principal budget {budget_id}: {already + amount} would exceed "
            f"{ceiling} over {window_h:.0f}h for {self.principal} "
            f"({already} already spent across prior sessions)"
        )


def parks_below_the_gate(
    ledger: PrincipalLedger,
    principal: str,
    budget_id: str,
    ceiling: Decimal,
    *,
    now: float | None = None,
    windows: int = 6,
    gate: float = 0.85,
    band: float = 0.15,
    min_hits: int = 3,
) -> StructuringSignal:
    """Spend that repeatedly stops just short of whatever gate is watching it.

    `structuring_signal` fires above a utilisation threshold, and any threshold
    has a just-under evasion by construction: four equal payments totalling
    84.99% of the ceiling trip nothing, and repeat every window forever.
    Lowering the gate does not fix it, it only moves it, and it costs
    legitimate traffic linearly. Measured over 3,000 synthetic legitimate runs:

        gate 0.85 -> 12.2% flagged      gate 0.60 -> 30.9%
        gate 0.75 -> 19.1%              gate 0.50 -> 40.0%

    and at every one of those the attacker parked one basis point below and was
    missed. So the answer is not a better threshold on one window.

    Landing in a narrow band just under the gate, window after window, is a
    signature in its own right. Real spend does not hug a line it cannot see; an
    agent shaping its behaviour to a limit does. This is the structuring argument
    applied to the detector's own threshold, which is where the adversary moved
    once the first one was closed.

    Advisory like the rest of this tier. It escalates and never blocks.
    """
    at = time.time() if now is None else now
    if ceiling <= 0:
        return StructuringSignal(0, Decimal(0), ceiling, 0, 0.0, 0.0)

    # Read the log directly. `entries_in_window` PRUNES as it reads, so walking
    # backwards through windows with it destroys the history being measured: the
    # first call evicts everything older than one window and every later window
    # then reports zero.
    with ledger._lock:
        history = list(ledger._index.get((principal, budget_id), ()))

    hits = 0
    utilisations: list[float] = []
    for index in range(windows):
        end = at - index * ledger.window_seconds
        start = end - ledger.window_seconds
        total = sum((e.amount for e in history if start <= e.at < end), Decimal(0))
        used = float(total / ceiling)
        utilisations.append(used)
        if gate - band <= used < gate:
            hits += 1

    reasons: list[str] = []
    if hits >= min_hits:
        reasons.append(
            f"{hits} of the last {windows} windows ended between "
            f"{gate - band:.0%} and {gate:.0%} of the {ceiling} ceiling, which is "
            f"spend shaped to stop just short of a limit rather than by the work"
        )
    total_now = sum(
        (e.amount for e in history if e.at >= at - ledger.window_seconds),
        Decimal(0),
    )
    return StructuringSignal(
        len(utilisations), total_now, ceiling, hits,
        0.0, 0.0, tuple(reasons),
    )


# --------------------------------------------------------------------------- #
# Cross-process
# --------------------------------------------------------------------------- #
@dataclass
class SharedPrincipalLedger(PrincipalLedger):
    """A ledger whose ceiling survives more than one process.

    `PrincipalLedger` synchronises on a `threading.RLock`, which is
    process-local. Measured, four OS processes against one ledger file and a
    ceiling of 100: **400 landed**. Each process loaded the log, saw nothing
    spent, reserved, and committed. That is not a corner case, a second
    gunicorn worker or a second k8s replica is the normal shape of a
    deployment, and each one is a fresh ceiling, which is precisely the
    session-restart escape this module was written to close.

    Three things have to be shared, not one, and missing any of them leaves the
    hole open:

    **Mutual exclusion.** An OS-level lock file, so the read-modify-write in
    `reserve` is atomic across processes and not merely across threads.

    **Committed spend.** The in-memory index is a snapshot from load time. Every
    transaction tails the log for bytes appended by anyone else, so `spent`
    reflects other processes' commits rather than this process's last look.

    **Outstanding holds.** The subtle one. Even with a shared log and a shared
    lock, two processes that each hold a reservation cannot see each other's,
    so both pass the ceiling check and both commit later. Holds, voids and
    settlements therefore live in a sidecar file rewritten under the same lock.
    They are TTL-bounded, so it stays small.

    POSIX only, single host. For multiple hosts the same `_transaction` seam
    takes a Redis or Postgres lock instead; `RedisUsedTokenStore` is the
    existing precedent for that shape.
    """

    #: What to do when the lock cannot be taken, a read-only mount, a full
    #: disk, a permissions change, and for a future Redis backend an unreachable
    #: server. "deny" refuses the action and counts it; "allow" is available
    #: because availability is sometimes worth more than a ceiling, and it is
    #: NOT the default and never silently chosen.
    #:
    #: There is no correct universal answer. What is not acceptable is an
    #: implicit one: this repository has already shipped six fail-opens whose
    #: whole shape was a control that stopped applying when its input was
    #: unusual, and reported success.
    on_unavailable: str = "deny"
    #: Count of transactions that could not reach the backend. Non-zero means
    #: the ceiling was not enforced for that many actions, whichever policy is
    #: set, and it is what an operator alerts on.
    unavailable_count: int = 0
    _offset: int = 0

    def __post_init__(self) -> None:
        if self.path is None:
            raise ValueError(
                "SharedPrincipalLedger needs a path: the file IS the shared "
                "state. Use PrincipalLedger for an in-memory ledger.")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        # Deliberately NOT `super().__post_init__()`, which reads the whole file
        # and then stats it separately for the offset. Anything another process
        # appended between those two calls would be skipped forever, and skipped
        # entries are spend this process cannot see: it would grant headroom
        # that is already gone. Starting at offset 0 and letting the first
        # transaction do the read means the load happens under the lock, which
        # is the only place it is safe.
        self._offset = 0

    # -- paths ------------------------------------------------------------- #
    @property
    def _lock_path(self) -> Path:
        return self.path.with_suffix(self.path.suffix + ".lock")

    @property
    def _sidecar_path(self) -> Path:
        return self.path.with_suffix(self.path.suffix + ".holds")

    # -- the seam ---------------------------------------------------------- #
    @contextmanager
    def _transaction(self):
        import fcntl

        with self._lock:                      # still needed: threads in THIS process
            if getattr(self, "_in_txn", False):
                yield                         # re-entrant, already holding the file lock
                return
            try:
                handle = open(self._lock_path, "a+b")
            except OSError as exc:
                self.unavailable_count += 1
                if self.on_unavailable == "allow":
                    # Explicitly chosen: proceed with THIS process's view, which
                    # is a ceiling per process rather than none at all.
                    #
                    # `_in_txn` is set here for the same reason it is set on the
                    # success path: `reserve` calls `spent`, which opens its own
                    # transaction. Without it the nested call re-enters, fails
                    # again, and counts again, one refused action reported as
                    # two backend outages, which is exactly the kind of inflated
                    # number an operator learns to ignore.
                    self._in_txn = True
                    try:
                        yield
                    finally:
                        self._in_txn = False
                    return
                raise LedgerUnavailable(
                    f"cannot reach the shared ledger at {self._lock_path}: "
                    f"{exc}. No ceiling was checked, so the action is refused "
                    f"(on_unavailable={self.on_unavailable!r})") from exc
            with handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                self._in_txn = True
                try:
                    self._sync_log()
                    self._load_sidecar()
                    yield
                    self._save_sidecar()
                finally:
                    self._in_txn = False
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    # -- shared committed spend -------------------------------------------- #
    def _sync_log(self) -> None:
        """Merge entries appended by other processes since the last look.

        Only whole lines are consumed. A partial final line is left unread and
        `_offset` is not advanced past it, so a torn append is picked up on the
        next transaction rather than dropped, under-counting is the failure
        direction that lets an attack through.
        """
        size = self.path.stat().st_size
        if size <= self._offset:
            return
        with self.path.open("rb") as handle:
            handle.seek(self._offset)
            raw = handle.read(size - self._offset)
        consumed, tail = 0, raw
        while True:
            idx = tail.find(b"\n")
            if idx < 0:
                break
            line, tail = tail[:idx], tail[idx + 1:]
            consumed += idx + 1
            text = line.decode("utf-8", "replace").strip()
            if not text:
                continue
            try:
                entry = LedgerEntry.from_dict(json.loads(text))
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
            key = (entry.principal, entry.budget_id)
            self._entries.append(entry)
            self._index.setdefault(key, []).append(entry)
            self._totals[key] = self._totals.get(key, Decimal(0)) + entry.amount
        self._offset += consumed

    def _append(self, entry: LedgerEntry) -> None:
        super()._append(entry)
        # Our own write is already merged in memory by `book`, so skip it on the
        # next sync rather than double counting it.
        try:
            self._offset = self.path.stat().st_size
        except OSError:
            pass

    # -- shared holds ------------------------------------------------------ #
    def _load_sidecar(self) -> None:
        try:
            raw = json.loads(self._sidecar_path.read_text())
        except (OSError, json.JSONDecodeError):
            return
        holds: dict = {}
        for item in raw.get("holds", []):
            try:
                hold = Hold(principal=item["principal"],
                            budget_id=item["budget_id"],
                            amount=Decimal(item["amount"]),
                            created_at=float(item["created_at"]),
                            hold_id=item["hold_id"],
                            ceiling=Decimal(item.get("ceiling", "0")))
            except (KeyError, ValueError, ArithmeticError):
                continue
            holds.setdefault((hold.principal, hold.budget_id), []).append(hold)
        # The sidecar is the ONLY source of truth for holds. An earlier version
        # merged `self._holds` back in on top of it, to preserve this process's
        # own Hold objects, but after a sync `self._holds` contains *every*
        # process's holds, so the merge resurrected holds their owners had
        # already released. Measured: 5 phantom holds pinning 50 of a 100
        # ceiling, and 70 landing where 100 should have.
        #
        # Nothing needs preserving. A hold created in this transaction is
        # written to the sidecar before the transaction ends, and `release`
        # matches on `hold_id` rather than object identity, so a caller's
        # reference still resolves after a sync replaces the objects.
        self._holds = holds
        self._reserved = {k: sum((h.amount for h in v), Decimal(0))
                          for k, v in holds.items()}
        self._voided |= set(raw.get("voided", []))

    def _save_sidecar(self) -> None:
        payload = {
            "holds": [{"principal": h.principal, "budget_id": h.budget_id,
                       "amount": str(h.amount), "created_at": h.created_at,
                       "hold_id": h.hold_id, "ceiling": str(h.ceiling)}
                      for group in self._holds.values() for h in group],
            # Bounded by the hold TTL in practice; trimmed to the ids still
            # referenced plus recent ones so the file cannot grow without limit.
            "voided": sorted(self._voided)[-4096:],
        }
        tmp = self._sidecar_path.with_suffix(self._sidecar_path.suffix + ".tmp")
        # Written through the same private-create path: the sidecar carries
        # identities and outstanding holds.
        with open_private_append(tmp) as fh:
            fh.write(json.dumps(payload))
        os.replace(tmp, self._sidecar_path)

    def release(self, hold: Hold | None) -> None:
        """Match by hold_id as well as identity.

        The base class pops by `is`, which is right in-process and wrong here:
        after a sync the list holds reconstructed Hold objects for the same
        reservation, so an identity match fails and the headroom is never
        returned.
        """
        if hold is None:
            return
        with self._transaction():
            key = (hold.principal, hold.budget_id)
            holds = self._holds.get(key)
            if not holds:
                return
            for i, existing in enumerate(holds):
                if existing is hold or existing.hold_id == hold.hold_id:
                    holds.pop(i)
                    break
            else:
                return
            self._reserved[key] = sum((h.amount for h in holds), Decimal(0))
            # The object goes back on the shelf. A refused action did not act on
            # it, so holding its identity forever would make one denial a
            # permanent one.
            if hold.identity:
                self._held_identities.get(key, set()).discard(hold.identity)


@dataclass
class PrincipalReservation:
    """`ValueReservation`'s shape, backed by holds on a shared ledger.

    The broker only ever calls `reserve`, then exactly one of `commit` or
    `release`, and it does not care which ledger is underneath. Presenting the
    same three methods is what lets a principal-scoped budget be dropped in
    where a session-scoped one was, which is the substitution MCP 2026-07-28
    forces: with the session handshake removed, a per-session ceiling counts
    over nothing.
    """

    allowed: bool
    reason: str
    _view: Any = None
    _holds: list = field(default_factory=list)
    _settled: bool = False
    _idempotency_key: str | None = None

    def commit(self) -> None:
        if self._settled:
            return
        self._settled = True
        for hold in self._holds:
            self._view.ledger.commit_hold(
                hold, session=self._view.session,
                idempotency_key=self._idempotency_key or "")

    def release(self) -> None:
        if self._settled:
            return
        self._settled = True
        for hold in self._holds:
            self._view.ledger.release(hold)
