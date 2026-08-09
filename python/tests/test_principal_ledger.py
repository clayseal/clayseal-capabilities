"""Principal-scoped budgets: aggregate limits that survive the session boundary.

The bug this closes is one line in every aggregate control in the field: the
ledger is constructed per session, so an attacker resets it by opening a second
conversation. `benchmarks/structuring.py` shows session-scoped containment
failing at four fragments and never recovering.

A persistent ledger has failure modes a session one does not, and those are what
most of this file tests: windows that never expire become lifetime quotas that
block all legitimate work, lost writes under-count and let attacks through,
duplicate writes over-count and block real work, and a wrong key silently
reintroduces the original bug.
"""
from __future__ import annotations

from decimal import Decimal

import pytest

from agentauth.capabilities.principal_ledger import (
    PrincipalBudgetView,
    PrincipalLedger,
)

CEILING = Decimal("10000")
TRACKED = {"send_money": ("amount", "usd_payout")}


def _view(ledger: PrincipalLedger, session: str = "s1",
          principal: str = "mandate:payouts") -> PrincipalBudgetView:
    return PrincipalBudgetView(
        ledger=ledger, principal=principal,
        ceilings={"usd_payout": CEILING}, tracked=TRACKED, session=session,
    )


def _spend(view: PrincipalBudgetView, amount: str, now: float | None = None) -> bool:
    args = {"amount": amount}
    ok, _ = view.would_allow("send_money", args, now=now)
    if ok:
        view.commit("send_money", args, now=now)
    return ok


# --------------------------------------------------------------------------- #
# The attack this exists to stop
# --------------------------------------------------------------------------- #
def test_structuring_across_sessions_is_contained():
    """Four sessions, each fragment individually under the ceiling."""
    ledger = PrincipalLedger()
    allowed = sum(
        _spend(_view(ledger, session=f"s{i}"), "2600") for i in range(4)
    )
    assert allowed == 3, "a fourth fragment of 2600 would cross a 10000 ceiling"
    assert ledger.spent("mandate:payouts", "usd_payout") == Decimal("7800")


def test_many_tiny_fragments_are_contained():
    """The limit is on the total, so granularity buys the attacker nothing."""
    ledger = PrincipalLedger()
    allowed = sum(_spend(_view(ledger, session=f"s{i}"), "100") for i in range(200))
    assert allowed == 100          # 100 x 100 = the ceiling exactly
    assert ledger.spent("mandate:payouts", "usd_payout") == CEILING


def test_a_separate_principal_has_its_own_ceiling():
    """Containment must not leak across mandates, or one busy agent starves
    every other one sharing the deployment."""
    ledger = PrincipalLedger()
    assert _spend(_view(ledger, principal="mandate:a"), "9000")
    assert _spend(_view(ledger, principal="mandate:b"), "9000")


# --------------------------------------------------------------------------- #
# Windows
# --------------------------------------------------------------------------- #
def test_spend_ages_out_of_the_window():
    """Without this the ceiling is a lifetime quota and eventually blocks
    everything, which is an outage rather than a control."""
    ledger = PrincipalLedger(window_seconds=3600)
    t0 = 1_000_000.0
    assert _spend(_view(ledger), "9000", now=t0)
    assert not _spend(_view(ledger), "9000", now=t0 + 60)      # still in window
    assert _spend(_view(ledger), "9000", now=t0 + 3601)        # aged out


def test_window_boundary_is_inclusive_of_recent_spend():
    ledger = PrincipalLedger(window_seconds=3600)
    t0 = 1_000_000.0
    _spend(_view(ledger), "9000", now=t0)
    assert ledger.spent("mandate:payouts", "usd_payout", now=t0 + 3599) == Decimal("9000")
    assert ledger.spent("mandate:payouts", "usd_payout", now=t0 + 3601) == Decimal("0")


# --------------------------------------------------------------------------- #
# Write integrity
# --------------------------------------------------------------------------- #
def test_idempotent_booking_does_not_double_count():
    """A retried tool call must not debit twice, or a reconnect blocks the
    principal out of work it never did."""
    ledger = PrincipalLedger()
    for _ in range(5):
        ledger.book("p", "usd_payout", Decimal("500"), idempotency_key="call-1")
    assert ledger.spent("p", "usd_payout") == Decimal("500")


def test_distinct_keys_both_count():
    ledger = PrincipalLedger()
    ledger.book("p", "usd_payout", Decimal("500"), idempotency_key="call-1")
    ledger.book("p", "usd_payout", Decimal("500"), idempotency_key="call-2")
    assert ledger.spent("p", "usd_payout") == Decimal("1000")


def test_ledger_survives_a_restart(tmp_path):
    """The whole point: a new process must not hand the attacker a fresh
    ceiling."""
    path = tmp_path / "ledger.jsonl"
    first = PrincipalLedger(path=path)
    assert _spend(_view(first), "9000")

    second = PrincipalLedger(path=path)      # simulates a restart
    assert second.spent("mandate:payouts", "usd_payout") == Decimal("9000")
    assert not _spend(_view(second), "2000")


def test_a_torn_final_line_is_skipped_not_fatal(tmp_path):
    """An interrupted append leaves a partial line. It was never acknowledged,
    so dropping it is correct; crashing on it would take the control offline,
    and offline is open."""
    path = tmp_path / "ledger.jsonl"
    ledger = PrincipalLedger(path=path)
    ledger.book("p", "usd_payout", Decimal("100"))
    with path.open("a") as fh:
        fh.write('{"principal": "p", "budget_id": "usd_pay')   # torn

    reopened = PrincipalLedger(path=path)
    assert reopened.spent("p", "usd_payout") == Decimal("100")


def test_totals_are_cached_but_verifiable():
    """A deliberate reversal, recorded rather than quietly made.

    The first version derived every total from the log on each read, so a lost
    write could not silently raise a ceiling. That cost 4.75 ms per read at
    20,000 entries, which is 100x the entire per-action enforcement stack and
    would have made the ledger the slowest thing in the request path.

    The property is now maintained by an explicit check rather than by
    construction: totals are cached, and `verify_totals` recomputes from the log
    and compares. That is weaker, and it is why the check is exercised here and
    after pruning rather than being assumed.
    """
    ledger = PrincipalLedger()
    ledger.book("p", "usd_payout", Decimal("100"))
    assert ledger.spent("p", "usd_payout") == Decimal("100")
    assert ledger.verify_totals()

    # Corrupting the log behind the cache is exactly what the check catches.
    ledger._index[("p", "usd_payout")].clear()
    assert not ledger.verify_totals()


# --------------------------------------------------------------------------- #
# View behaviour
# --------------------------------------------------------------------------- #
def test_untracked_tools_pass_through():
    view = _view(PrincipalLedger())
    ok, reason = view.would_allow("read_file", {"path": "/app/x"})
    assert ok and "not tracked" in reason


def test_denial_names_the_prior_cross_session_spend():
    """An operator reading the log has to be able to tell that the block came
    from another session, or the denial looks arbitrary."""
    ledger = PrincipalLedger()
    _spend(_view(ledger, session="yesterday"), "9500")
    ok, reason = _view(ledger, session="today").would_allow(
        "send_money", {"amount": "1000"})
    assert not ok
    assert "9500" in reason and "prior sessions" in reason


@pytest.mark.parametrize("bad", [None, True, {"nested": 1}, "not-a-number"])
def test_unparseable_amounts_do_not_debit(bad):
    """A malformed amount must not book a zero and quietly consume an effect
    slot, nor raise into the enforcement path."""
    ledger = PrincipalLedger()
    view = _view(ledger)
    ok, _ = view.would_allow("send_money", {"amount": bad})
    assert ok
    view.commit("send_money", {"amount": bad})
    assert ledger.spent("mandate:payouts", "usd_payout") == Decimal("0")


# --------------------------------------------------------------------------- #
# Structuring detection: spend shaped by the limit rather than by the work
# --------------------------------------------------------------------------- #
def _book_all(ledger: PrincipalLedger, amounts, principal="p"):
    for i, a in enumerate(amounts):
        ledger.book(principal, "usd_payout", Decimal(str(a)), idempotency_key=f"k{i}")


def test_uniform_split_against_the_ceiling_is_flagged():
    """Four payments of 2500 under a 10000 ceiling. No round-number test sees
    this, and it is the entire attack."""
    from agentauth.capabilities.principal_ledger import structuring_signal

    ledger = PrincipalLedger()
    _book_all(ledger, ["2500", "2500", "2500", "2500"])
    sig = structuring_signal(ledger, "p", "usd_payout", CEILING)
    assert sig.suspicious
    assert sig.fragments == 4
    assert "divided total" in " ".join(sig.reasons)


def test_just_under_parking_is_flagged():
    """The classic signature: repeated amounts in the top band below the limit."""
    from agentauth.capabilities.principal_ledger import structuring_signal

    ledger = PrincipalLedger(window_seconds=86400)
    _book_all(ledger, ["9000", "9000", "9000", "9000"])
    sig = structuring_signal(ledger, "p", "usd_payout", CEILING)
    assert sig.suspicious and sig.just_under == 4
    assert "parked between" in " ".join(sig.reasons)


def test_varied_business_payments_are_not_flagged():
    """The false-positive case that decides whether anyone leaves this on.
    Real invoice runs vary in size and do not consume the whole ceiling."""
    from agentauth.capabilities.principal_ledger import structuring_signal

    ledger = PrincipalLedger()
    _book_all(ledger, ["1200.50", "340", "2750.25", "89.99", "1500"])
    sig = structuring_signal(ledger, "p", "usd_payout", CEILING)
    assert not sig.suspicious, sig.reasons


def test_uniform_but_low_utilisation_is_not_flagged():
    """Payroll is uniform. Uniformity only counts as evidence when the
    fragments also consume most of the ceiling, which is what makes the limit
    look like the binding constraint."""
    from agentauth.capabilities.principal_ledger import structuring_signal

    ledger = PrincipalLedger()
    _book_all(ledger, ["100", "100", "100", "100", "100"])
    sig = structuring_signal(ledger, "p", "usd_payout", CEILING)
    assert not sig.suspicious


def test_a_single_large_payment_is_not_structuring():
    """One payment cannot be a split, whatever its size."""
    from agentauth.capabilities.principal_ledger import structuring_signal

    ledger = PrincipalLedger()
    _book_all(ledger, ["9900"])
    sig = structuring_signal(ledger, "p", "usd_payout", CEILING)
    assert not sig.suspicious


def test_signal_respects_the_window():
    """Yesterday's split is not today's evidence."""
    from agentauth.capabilities.principal_ledger import structuring_signal

    ledger = PrincipalLedger(window_seconds=3600)
    t0 = 1_000_000.0
    for i in range(4):
        ledger.book("p", "usd_payout", Decimal("2500"), idempotency_key=f"k{i}", now=t0)
    assert structuring_signal(ledger, "p", "usd_payout", CEILING, now=t0).suspicious
    assert not structuring_signal(ledger, "p", "usd_payout", CEILING, now=t0 + 7200).suspicious


# --------------------------------------------------------------------------- #
# Adversarial: four attacks that worked against the first version of this file
# --------------------------------------------------------------------------- #
def test_idempotency_key_reuse_cannot_launder_spend():
    """The key came from agent-controlled tool arguments, so an injected agent
    reused one and moved 40000 against a 10000 ceiling while the ledger booked
    5000. Now scoped to session AND amount."""
    ledger = PrincipalLedger()
    moved = Decimal("0")
    for i in range(8):
        v = _view(ledger, session=f"s{i}")
        args = {"amount": "5000", "_idempotency_key": "SAME-KEY"}
        ok, _ = v.authorize("send_money", args)
        if ok:
            v.commit("send_money", args)
            moved += Decimal("5000")
    assert moved <= CEILING
    assert ledger.spent("mandate:payouts", "usd_payout") == moved


def test_idempotency_still_dedupes_a_genuine_retry():
    """The fix must not break what idempotency is for: one session, one amount,
    the same key twice is one debit."""
    ledger = PrincipalLedger()
    for _ in range(3):
        ledger.book("p", "usd_payout", Decimal("500"),
                    session="s1", idempotency_key="call-1")
    assert ledger.spent("p", "usd_payout") == Decimal("500")


def test_concurrent_sessions_cannot_race_past_the_ceiling():
    """would_allow then commit is check-then-act: eight concurrent sessions
    each passed and each committed. `authorize` holds under the same lock."""
    import threading

    ledger = PrincipalLedger()
    committed = []
    barrier = threading.Barrier(8)

    def racer(i):
        v = _view(ledger, session=f"s{i}")
        args = {"amount": "5000"}
        ok, _ = v.authorize("send_money", args)
        barrier.wait()
        if ok:
            v.commit("send_money", args)
            committed.append(Decimal("5000"))

    threads = [threading.Thread(target=racer, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(committed, Decimal("0")) <= CEILING


def test_jittered_fragments_do_not_evade_detection():
    """10% jitter defeated the uniformity signal while the same money moved.
    The fragmentation signal does not depend on the amounts resembling each
    other."""
    from agentauth.capabilities.principal_ledger import structuring_signal

    for amounts in (["2500", "2475", "2520", "2505"],       # 1%
                    ["2500", "2250", "2750", "2500"],       # 10%
                    ["2500", "1750", "3250", "2500"]):      # 30%
        ledger = PrincipalLedger()
        _book_all(ledger, amounts)
        assert structuring_signal(ledger, "p", "usd_payout", CEILING).suspicious, amounts


def test_running_totals_never_drift_from_the_log():
    """The totals are an optimisation, and an optimisation that drifts from its
    log is how a ceiling silently rises."""
    ledger = PrincipalLedger(window_seconds=100)
    t0 = 1_000_000.0
    for i in range(50):
        ledger.book("p", "usd_payout", Decimal("10"),
                    idempotency_key=f"k{i}", now=t0 + i)
    assert ledger.verify_totals()
    ledger.spent("p", "usd_payout", now=t0 + 120)     # forces a prune
    assert ledger.verify_totals()


def test_reads_stay_cheap_at_scale():
    """4.75 ms per read at 20k entries would have made the ledger the slowest
    thing in the enforcement path, against 35 us for the whole stack."""
    import time

    ledger = PrincipalLedger()
    for i in range(20_000):
        ledger.book("p", "usd_payout", Decimal("1"), idempotency_key=f"k{i}")
    start = time.perf_counter()
    for _ in range(100):
        ledger.spent("p", "usd_payout")
    per_call_ms = (time.perf_counter() - start) / 100 * 1000
    assert per_call_ms < 0.5, f"{per_call_ms:.2f} ms per read"


# --------------------------------------------------------------------------- #
# Sign. Found by an adversarial audit of this module, not by review.
# --------------------------------------------------------------------------- #
def test_a_negative_amount_cannot_lift_the_ceiling_for_other_sessions():
    """One negative call used to be a global disable switch.

    `reserve` adds the amount straight into `_reserved`, which is keyed by
    (principal, budget) rather than by session. A single authorize() carrying
    -1,000,000,000 therefore held a vast negative amount against the principal,
    and every concurrent and subsequent session of that principal passed its
    ceiling check. Measured at 499,950 moved against a ceiling of 10,000, with
    nothing on disk to show the ledger had been touched.
    """
    ledger = PrincipalLedger()
    ceilings = {"usd_payout": Decimal("10000")}
    tracked = {"send_money": ("amount", "usd_payout")}

    def view(session):
        return PrincipalBudgetView(ledger=ledger, principal="mandate:payouts",
                                   ceilings=ceilings, tracked=tracked, session=session)

    view("attacker").authorize("send_money", {"amount": "-1000000000"})

    moved = Decimal("0")
    for i in range(50):
        v = view(f"s{i}")
        ok, _ = v.authorize("send_money", {"amount": "9999"})
        if ok:
            v.commit("send_money", {"amount": "9999"})
            moved += Decimal("9999")
    assert moved <= Decimal("10000"), f"{moved} moved against a 10000 ceiling"


def test_a_negative_booking_cannot_manufacture_headroom():
    """The `book` form of the same defect.

    A booked credit drove the window total down, so `spent`, `remaining` and
    `would_exceed` all reported headroom that did not exist, and
    `verify_totals` still returned True because the cache and the log agreed on
    the wrong number. 180,000 was moved against a 10,000 ceiling this way.
    """
    ledger = PrincipalLedger()
    with pytest.raises(ValueError):
        ledger.book("mandate:payouts", "usd_payout", Decimal("-9000"))
    assert ledger.spent("mandate:payouts", "usd_payout") == Decimal("0")
    assert ledger.verify_totals()


@pytest.mark.parametrize("bad", ["-1", "0", "NaN", "Infinity", "-Infinity"])
def test_non_positive_and_non_finite_amounts_are_not_tracked(bad):
    ledger = PrincipalLedger()
    v = PrincipalBudgetView(
        ledger=ledger, principal="p", ceilings={"b": Decimal("100")},
        tracked={"send_money": ("amount", "b")}, session="s")
    ok, reason = v.authorize("send_money", {"amount": bad})
    v.commit("send_money", {"amount": bad})
    assert ledger.spent("p", "b") == Decimal("0")
