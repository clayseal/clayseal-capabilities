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
import threading
import time
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path
from typing import Any

# Spend older than the window no longer counts against the ceiling. A day is the
# usual reporting period for the controls this imitates; callers should set it
# from policy rather than relying on the default.
DEFAULT_WINDOW_SECONDS = 24 * 60 * 60


@dataclass(frozen=True)
class LedgerEntry:
    principal: str
    budget_id: str
    amount: Decimal
    at: float
    session: str = ""
    idempotency_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal": self.principal, "budget_id": self.budget_id,
            "amount": str(self.amount), "at": self.at,
            "session": self.session, "idempotency_key": self.idempotency_key,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "LedgerEntry":
        return cls(
            principal=d["principal"], budget_id=d["budget_id"],
            amount=Decimal(d["amount"]), at=float(d["at"]),
            session=d.get("session", ""), idempotency_key=d.get("idempotency_key", ""),
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
    _lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)

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

    def _append(self, entry: LedgerEntry) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as fh:
            fh.write(json.dumps(entry.to_dict()) + "\n")
            fh.flush()

    # -- queries ------------------------------------------------------------
    def spent(self, principal: str, budget_id: str, *, now: float | None = None) -> Decimal:
        """Total booked for this principal and budget inside the window."""
        cutoff = (time.time() if now is None else now) - self.window_seconds
        with self._lock:
            return sum(
                (e.amount for e in self._entries
                 if e.principal == principal and e.budget_id == budget_id and e.at >= cutoff),
                Decimal("0"),
            )

    def entries_in_window(self, principal: str, budget_id: str,
                          *, now: float | None = None) -> list[LedgerEntry]:
        cutoff = (time.time() if now is None else now) - self.window_seconds
        with self._lock:
            return [e for e in self._entries
                    if e.principal == principal and e.budget_id == budget_id and e.at >= cutoff]

    # -- mutation -----------------------------------------------------------
    def book(self, principal: str, budget_id: str, amount: Decimal, *,
             session: str = "", idempotency_key: str = "",
             now: float | None = None) -> LedgerEntry:
        """Record spend. Idempotent on ``idempotency_key`` within the window.

        The idempotency check exists because a retried tool call must not debit
        twice, and a session view replaying its commitments after a reconnect
        would otherwise double-count the principal into a block.
        """
        at = time.time() if now is None else now
        entry = LedgerEntry(principal, budget_id, amount, at, session, idempotency_key)
        with self._lock:
            if idempotency_key:
                cutoff = at - self.window_seconds
                for existing in self._entries:
                    if (existing.idempotency_key == idempotency_key
                            and existing.principal == principal
                            and existing.budget_id == budget_id
                            and existing.at >= cutoff):
                        return existing
            self._append(entry)
            self._entries.append(entry)
        return entry

    def would_exceed(self, principal: str, budget_id: str, amount: Decimal,
                     ceiling: Decimal, *, now: float | None = None) -> bool:
        return self.spent(principal, budget_id, now=now) + amount > ceiling

    def remaining(self, principal: str, budget_id: str, ceiling: Decimal,
                  *, now: float | None = None) -> Decimal:
        return max(Decimal("0"), ceiling - self.spent(principal, budget_id, now=now))


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

    **Uniformity at high utilisation.** An amount divided into equal parts is
    the signature of a split rather than of work arriving. Real invoice runs
    vary; a divided total does not. Uniformity alone is not evidence, since
    payroll is uniform too, so it only counts when the fragments also consume
    most of the ceiling, which is what makes it look like a limit was the
    binding constraint rather than the business.
    """
    entries = ledger.entries_in_window(principal, budget_id, now=now)
    amounts = [e.amount for e in entries]
    total = sum(amounts, Decimal("0"))
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
    return StructuringSignal(len(amounts), total, ceiling, just_under,
                             uniformity, tuple(reasons))


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

    def _amount(self, tool_name: str, args: dict[str, Any]) -> tuple[str, Decimal] | None:
        spec = self.tracked.get(tool_name)
        if spec is None:
            return None
        arg_name, budget_id = spec
        raw = args.get(arg_name)
        if not isinstance(raw, (int, float, str, Decimal)) or isinstance(raw, bool):
            return None
        try:
            return budget_id, Decimal(str(raw))
        except (ValueError, ArithmeticError):
            return None

    def would_allow(self, tool_name: str, args: dict[str, Any],
                    *, now: float | None = None) -> tuple[bool, str]:
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

    def commit(self, tool_name: str, args: dict[str, Any],
               *, now: float | None = None) -> None:
        parsed = self._amount(tool_name, args)
        if parsed is None:
            return
        budget_id, amount = parsed
        self.ledger.book(
            self.principal, budget_id, amount, session=self.session,
            idempotency_key=str(args.get("_idempotency_key") or ""), now=now,
        )
