"""Attacks on the persistent ledger, which is now the load-bearing component.

    python -m benchmarks.stress_principal_ledger

`stress_aggregation.py` established that the session-restart escape is real: a
fresh session is a fresh ledger, so an attacker who can open a second
conversation gets a second ceiling. `principal_ledger.py` is the answer to that,
which makes it the thing an attacker now has a reason to attack. It is also the
newest code in the enforcement floor and the least fuzzed.

The axes below are the ones a cumulative control actually loses to, ordered by
how much they would cost if true. Every one is deterministic and offline: the
clock is injected, so nothing here depends on wall time.

Already found and fixed by this harness:

- **Reserve/commit desync.** Reserve the ceiling, wait out the 300s hold TTL,
  reserve again (the first hold has been voided so the headroom is free), commit
  both. 200 booked against a ceiling of 100, silently, with no clock control.
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import threading
from decimal import Decimal
from pathlib import Path

from clayseal.capabilities.principal_ledger import PrincipalLedger

CEILING = Decimal(100)
TOOL_MONEY = "payments.transfer"


def _fresh(**kw) -> PrincipalLedger:
    return PrincipalLedger(**kw)


# --------------------------------------------------------------------------- #
def axis_reserve_commit_desync() -> dict:
    """Void a hold by waiting, re-let its headroom, then commit it anyway."""
    led = _fresh(reservation_ttl_seconds=60.0)
    a = led.reserve("p", "b", CEILING, CEILING, now=0.0)
    b = led.reserve("p", "b", CEILING, CEILING, now=120.0)
    led.commit_hold(a, now=121.0)
    led.commit_hold(b, now=122.0)
    landed = led.spent("p", "b", now=123.0)
    return {"axis": "reserve/commit desync (TTL)", "landed": int(landed),
            "escaped": landed > CEILING and not led.late_breaches(),
            "note": (f"{int(landed)} booked; "
                     f"{len(led.late_breaches())} breach(es) reported")}


def axis_double_commit() -> dict:
    """One hold, committed twice."""
    led = _fresh()
    h = led.reserve("p", "b", CEILING, CEILING)
    led.commit_hold(h, session="s")
    led.commit_hold(h, session="s")
    landed = led.spent("p", "b")
    return {"axis": "double commit of one hold", "landed": int(landed),
            "escaped": landed > CEILING}


def axis_window_boundary() -> dict:
    """Spend ages out on the window. Intended, the check is the boundary.

    A ceiling with no window is a lifetime quota, so aging out is by design.
    What must not happen is aging out EARLY, which would let the same spend be
    repeated inside one nominal window.
    """
    led = _fresh(window_seconds=1000)
    led.book("p", "b", CEILING, now=0.0)
    just_inside = led.spent("p", "b", now=999.0)
    return {"axis": "window boundary (early expiry)",
            "landed": int(CEILING - just_inside),
            "escaped": just_inside < CEILING,
            "note": f"{int(just_inside)} of 100 still counted at t+999 of 1000"}


def axis_idempotency_cross_session() -> dict:
    """One idempotency key reused across sessions must not suppress the debit."""
    led = _fresh()
    for i in range(10):
        led.book("p", "b", Decimal(50), session=f"s{i}", idempotency_key="same")
    landed = led.spent("p", "b")
    return {"axis": "idempotency key across sessions", "landed": int(landed),
            "escaped": landed < 500,
            "note": "reuse across sessions must book normally"}


def axis_idempotency_amount_swap() -> dict:
    """Same key, larger amount: a small authorized debit laundering a big one.

    The escape is the ledger DEDUPING the second call, which would move 10,000
    while booking 1. Booking both is the correct outcome, so the check is that
    the total reflects both, not that it stays under a ceiling. `book` is the
    recording layer and takes no ceiling; `reserve` is where a ceiling lives.
    That distinction is why the first version of this axis reported an escape
    here: it compared a booking total against a ceiling that booking never
    claimed to enforce.
    """
    led = _fresh()
    led.book("p", "b", Decimal(1), session="s", idempotency_key="k")
    led.book("p", "b", Decimal(10_000), session="s", idempotency_key="k")
    landed = led.spent("p", "b")
    return {"axis": "idempotency, amount swapped", "landed": int(landed),
            "escaped": landed < 10_001,
            "note": "a mismatched amount must not dedupe (both must book)"}


def axis_concurrent_reserve() -> dict:
    """32 threads racing one ceiling. Check-then-act would let them all through."""
    led = _fresh()
    granted: list = []
    barrier = threading.Barrier(32)
    lock = threading.Lock()

    def go():
        barrier.wait()
        h = led.reserve("p", "b", Decimal(10), CEILING)
        if h is not None:
            with lock:
                granted.append(h)

    threads = [threading.Thread(target=go) for _ in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for h in granted:
        led.commit_hold(h)
    landed = led.spent("p", "b")
    return {"axis": "32 concurrent reservations", "landed": int(landed),
            "escaped": landed > CEILING,
            "note": f"{len(granted)} of 32 granted"}


def axis_torn_tail() -> dict:
    """A half-written last line must not take the entries before it with it.

    Crash consistency, and the direction that matters is under-counting: a
    ledger that loses writes reports headroom that was already spent.
    """
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "ledger.jsonl"
        led = _fresh(path=path)
        for i in range(10):
            led.book("p", "b", Decimal(10), session=f"s{i}")
        raw = path.read_bytes()
        path.write_bytes(raw[: len(raw) - 12])       # truncate mid-record
        reloaded = _fresh(path=path)
        landed = reloaded.spent("p", "b")
    return {"axis": "torn tail on reload", "landed": int(landed),
            "escaped": landed < 90,
            "note": f"{int(landed)} of 100 survived a truncated last record"}


def axis_persisted_double_book() -> dict:
    """Reload from disk and re-book the same idempotent debit."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "ledger.jsonl"
        led = _fresh(path=path)
        led.book("p", "b", CEILING, session="s", idempotency_key="k")
        reloaded = _fresh(path=path)
        reloaded.book("p", "b", CEILING, session="s", idempotency_key="k")
        landed = reloaded.spent("p", "b")
    return {"axis": "re-book across a reload", "landed": int(landed),
            "escaped": landed > CEILING,
            "note": "idempotency must survive a restart"}


def axis_precision() -> dict:
    """Amounts below the quantum. If they round to zero they are free."""
    led = _fresh()
    tiny = Decimal("0.0001")
    for _ in range(2_000_000 // 1000):        # 2,000 debits
        led.book("p", "b", tiny)
    landed = led.spent("p", "b")
    expected = tiny * 2000
    return {"axis": "sub-quantum amounts", "landed": float(landed),
            "escaped": landed < expected / 2,
            "note": f"2,000 x {tiny} booked as {landed} (expected {expected})"}


def axis_absurd_amounts() -> dict:
    """The fail-open family that every other boundary here gave up."""
    led = _fresh()
    survived = True
    for raw in ("1e999", "Infinity", "NaN", "-1", "0"):
        try:
            h = led.reserve("p", "b", Decimal(raw), CEILING)
            if h is not None:
                survived = False          # granted an absurd reservation
        except (ValueError, ArithmeticError):
            pass                          # refusing is correct
        except Exception:                 # noqa: BLE001
            survived = False              # raising something else is not
    return {"axis": "absurd reservation amounts", "landed": 0,
            "escaped": not survived,
            "note": "1e999 / Infinity / NaN / negative / zero"}


def axis_clock_rewind() -> dict:
    """A caller-supplied clock that goes backwards must not create headroom."""
    led = _fresh(window_seconds=1000)
    led.book("p", "b", CEILING, now=500.0)
    rewound = led.spent("p", "b", now=0.0)
    return {"axis": "clock rewind", "landed": int(CEILING - rewound),
            "escaped": rewound < CEILING,
            "note": f"{int(rewound)} of 100 visible from an earlier now"}


def axis_delegation_splitting() -> dict:
    """A parent spawns sub-agents; each used to get its own ceiling.

    The plan calls this axis "unclosed by construction, and where MCP
    deployments live", and it was: every sub-agent has its own `sub`, therefore
    its own `principal_key`, therefore its own ceiling. Measured at 600 against
    a ceiling of 100 for a parent plus five delegates. A per-delegate ceiling is
    not a ceiling, anyone who can spawn sub-agents mints headroom.
    """
    from clayseal.capabilities.principal_ledger import (
        PrincipalBudgetView,
        principal_chain,
        principal_key,
    )
    from clayseal.core.authority_binding import AuthorityBinding

    led = _fresh()

    def binding(sub, chain=()):
        return AuthorityBinding(subject_id=sub, authority_id="a",
                                issuer="https://corp.example",
                                delegation_chain=list(chain))

    landed = Decimal(0)
    people = [binding("parent")] + [binding(f"sub-{n}", ["parent"])
                                    for n in range(5)]
    for i, b in enumerate(people):
        view = PrincipalBudgetView(
            ledger=led, principal=principal_key(b), chain=principal_chain(b),
            ceilings={"b": CEILING}, tracked={TOOL_MONEY: ("amount", "b")},
            session=b.subject_id)
        args = {"amount": "100"}
        allowed, _ = view.authorize(TOOL_MONEY, args, now=float(i))
        if allowed:
            view.commit(TOOL_MONEY, args, now=float(i))
            landed += 100
    return {"axis": "delegation splitting (1 + 5)", "landed": int(landed),
            "escaped": landed > CEILING,
            "note": "each delegate books against every ancestor's ceiling too"}


def axis_forged_delegation_chain() -> dict:
    """A claims dict naming a victim as its parent.

    Now that a delegate's spend books against its ancestors, a forged chain is
    an attack on someone ELSE's ceiling: name the victim as parent and exhaust
    it. `delegation_chain` is in `AUTHORITY_FIELDS` so an adapter strips it.
    """
    from clayseal.capabilities.identity_adapters import oidc
    from clayseal.capabilities.principal_ledger import principal_chain

    forged = oidc.provider.to_binding(
        {"subject_id": "attacker", "iss": "https://corp.example",
         "delegation_chain": ["victim"]})
    chain = principal_chain(forged)
    return {"axis": "forged delegation chain", "landed": len(chain),
            "escaped": bool(chain),
            "note": "a claims dict must not name its own ancestors"}


AXES = (axis_delegation_splitting, axis_forged_delegation_chain,
        axis_reserve_commit_desync, axis_double_commit, axis_window_boundary,
        axis_idempotency_cross_session, axis_idempotency_amount_swap,
        axis_concurrent_reserve, axis_torn_tail, axis_persisted_double_book,
        axis_precision, axis_absurd_amounts, axis_clock_rewind)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--json", type=Path, default=None)
    args = p.parse_args(argv)

    rows = [axis() for axis in AXES]
    head = f"{'axis':<34}{'landed':>12}{'verdict':>12}"
    print("attacks on the principal ledger (ceiling 100)\n")
    print(head)
    print("-" * len(head))
    for r in rows:
        print(f"{r['axis']:<34}{r['landed']:>12}"
              f"{('ESCAPED' if r['escaped'] else 'contained'):>12}")
    print()
    for r in rows:
        if r.get("note"):
            print(f"  {r['axis']}: {r['note']}")
    escaped = [r["axis"] for r in rows if r["escaped"]]
    print(f"\n{len(escaped)} of {len(rows)} axes escape.")
    if escaped:
        print("residual: " + "; ".join(escaped))
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(rows, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
