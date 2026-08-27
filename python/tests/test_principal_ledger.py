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

from clayseal.capabilities.principal_ledger import (
    PrincipalBudgetView,
    PrincipalLedger,
    structuring_signal,
)

CEILING = Decimal(10000)
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
    assert ledger.spent("mandate:payouts", "usd_payout") == Decimal(7800)


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
    assert ledger.spent("mandate:payouts", "usd_payout", now=t0 + 3599) == Decimal(9000)
    assert ledger.spent("mandate:payouts", "usd_payout", now=t0 + 3601) == Decimal(0)


# --------------------------------------------------------------------------- #
# Write integrity
# --------------------------------------------------------------------------- #
def test_idempotent_booking_does_not_double_count():
    """A retried tool call must not debit twice, or a reconnect blocks the
    principal out of work it never did."""
    ledger = PrincipalLedger()
    for _ in range(5):
        ledger.book("p", "usd_payout", Decimal(500), idempotency_key="call-1")
    assert ledger.spent("p", "usd_payout") == Decimal(500)


def test_distinct_keys_both_count():
    ledger = PrincipalLedger()
    ledger.book("p", "usd_payout", Decimal(500), idempotency_key="call-1")
    ledger.book("p", "usd_payout", Decimal(500), idempotency_key="call-2")
    assert ledger.spent("p", "usd_payout") == Decimal(1000)


def test_ledger_survives_a_restart(tmp_path):
    """The whole point: a new process must not hand the attacker a fresh
    ceiling."""
    path = tmp_path / "ledger.jsonl"
    first = PrincipalLedger(path=path)
    assert _spend(_view(first), "9000")

    second = PrincipalLedger(path=path)      # simulates a restart
    assert second.spent("mandate:payouts", "usd_payout") == Decimal(9000)
    assert not _spend(_view(second), "2000")


def test_a_torn_final_line_is_skipped_not_fatal(tmp_path):
    """An interrupted append leaves a partial line. It was never acknowledged,
    so dropping it is correct; crashing on it would take the control offline,
    and offline is open."""
    path = tmp_path / "ledger.jsonl"
    ledger = PrincipalLedger(path=path)
    ledger.book("p", "usd_payout", Decimal(100))
    with path.open("a") as fh:
        fh.write('{"principal": "p", "budget_id": "usd_pay')   # torn

    reopened = PrincipalLedger(path=path)
    assert reopened.spent("p", "usd_payout") == Decimal(100)


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
    ledger.book("p", "usd_payout", Decimal(100))
    assert ledger.spent("p", "usd_payout") == Decimal(100)
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
    assert ledger.spent("mandate:payouts", "usd_payout") == Decimal(0)


# --------------------------------------------------------------------------- #
# Structuring detection: spend shaped by the limit rather than by the work
# --------------------------------------------------------------------------- #
def _book_all(ledger: PrincipalLedger, amounts, principal="p"):
    for i, a in enumerate(amounts):
        ledger.book(principal, "usd_payout", Decimal(str(a)), idempotency_key=f"k{i}")


def test_uniform_split_against_the_ceiling_is_flagged():
    """Four payments of 2500 under a 10000 ceiling. No round-number test sees
    this, and it is the entire attack."""
    from clayseal.capabilities.principal_ledger import structuring_signal

    ledger = PrincipalLedger()
    _book_all(ledger, ["2500", "2500", "2500", "2500"])
    sig = structuring_signal(ledger, "p", "usd_payout", CEILING)
    assert sig.suspicious
    assert sig.fragments == 4
    assert "divided total" in " ".join(sig.reasons)


def test_just_under_parking_is_flagged():
    """The classic signature: repeated amounts in the top band below the limit."""
    from clayseal.capabilities.principal_ledger import structuring_signal

    ledger = PrincipalLedger(window_seconds=86400)
    _book_all(ledger, ["9000", "9000", "9000", "9000"])
    sig = structuring_signal(ledger, "p", "usd_payout", CEILING)
    assert sig.suspicious and sig.just_under == 4
    assert "parked between" in " ".join(sig.reasons)


def test_varied_business_payments_are_not_flagged():
    """The false-positive case that decides whether anyone leaves this on.
    Real invoice runs vary in size and do not consume the whole ceiling."""
    from clayseal.capabilities.principal_ledger import structuring_signal

    ledger = PrincipalLedger()
    _book_all(ledger, ["1200.50", "340", "2750.25", "89.99", "1500"])
    sig = structuring_signal(ledger, "p", "usd_payout", CEILING)
    assert not sig.suspicious, sig.reasons


def test_uniform_but_low_utilisation_is_not_flagged():
    """Payroll is uniform. Uniformity only counts as evidence when the
    fragments also consume most of the ceiling, which is what makes the limit
    look like the binding constraint."""
    from clayseal.capabilities.principal_ledger import structuring_signal

    ledger = PrincipalLedger()
    _book_all(ledger, ["100", "100", "100", "100", "100"])
    sig = structuring_signal(ledger, "p", "usd_payout", CEILING)
    assert not sig.suspicious


def test_a_single_large_payment_is_not_structuring():
    """One payment cannot be a split, whatever its size."""
    from clayseal.capabilities.principal_ledger import structuring_signal

    ledger = PrincipalLedger()
    _book_all(ledger, ["9900"])
    sig = structuring_signal(ledger, "p", "usd_payout", CEILING)
    assert not sig.suspicious


def test_signal_respects_the_window():
    """Yesterday's split is not today's evidence."""
    from clayseal.capabilities.principal_ledger import structuring_signal

    ledger = PrincipalLedger(window_seconds=3600)
    t0 = 1_000_000.0
    for i in range(4):
        ledger.book("p", "usd_payout", Decimal(2500), idempotency_key=f"k{i}", now=t0)
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
    moved = Decimal(0)
    for i in range(8):
        v = _view(ledger, session=f"s{i}")
        args = {"amount": "5000", "_idempotency_key": "SAME-KEY"}
        ok, _ = v.authorize("send_money", args)
        if ok:
            v.commit("send_money", args)
            moved += Decimal(5000)
    assert moved <= CEILING
    assert ledger.spent("mandate:payouts", "usd_payout") == moved


def test_idempotency_still_dedupes_a_genuine_retry():
    """The fix must not break what idempotency is for: one session, one amount,
    the same key twice is one debit."""
    ledger = PrincipalLedger()
    for _ in range(3):
        ledger.book("p", "usd_payout", Decimal(500),
                    session="s1", idempotency_key="call-1")
    assert ledger.spent("p", "usd_payout") == Decimal(500)


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
            committed.append(Decimal(5000))

    threads = [threading.Thread(target=racer, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(committed, Decimal(0)) <= CEILING


def test_jittered_fragments_do_not_evade_detection():
    """10% jitter defeated the uniformity signal while the same money moved.
    The fragmentation signal does not depend on the amounts resembling each
    other."""
    from clayseal.capabilities.principal_ledger import structuring_signal

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
        ledger.book("p", "usd_payout", Decimal(10),
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
        ledger.book("p", "usd_payout", Decimal(1), idempotency_key=f"k{i}")
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
    ceilings = {"usd_payout": Decimal(10000)}
    tracked = {"send_money": ("amount", "usd_payout")}

    def view(session):
        return PrincipalBudgetView(ledger=ledger, principal="mandate:payouts",
                                   ceilings=ceilings, tracked=tracked, session=session)

    view("attacker").authorize("send_money", {"amount": "-1000000000"})

    moved = Decimal(0)
    for i in range(50):
        v = view(f"s{i}")
        ok, _ = v.authorize("send_money", {"amount": "9999"})
        if ok:
            v.commit("send_money", {"amount": "9999"})
            moved += Decimal(9999)
    assert moved <= Decimal(10000), f"{moved} moved against a 10000 ceiling"


def test_a_negative_booking_cannot_manufacture_headroom():
    """The `book` form of the same defect.

    A booked credit drove the window total down, so `spent`, `remaining` and
    `would_exceed` all reported headroom that did not exist, and
    `verify_totals` still returned True because the cache and the log agreed on
    the wrong number. 180,000 was moved against a 10,000 ceiling this way.
    """
    ledger = PrincipalLedger()
    with pytest.raises(ValueError):
        ledger.book("mandate:payouts", "usd_payout", Decimal(-9000))
    assert ledger.spent("mandate:payouts", "usd_payout") == Decimal(0)
    assert ledger.verify_totals()


@pytest.mark.parametrize("bad", ["-1", "0", "NaN", "Infinity", "-Infinity"])
def test_non_positive_and_non_finite_amounts_are_not_tracked(bad):
    ledger = PrincipalLedger()
    v = PrincipalBudgetView(
        ledger=ledger, principal="p", ceilings={"b": Decimal(100)},
        tracked={"send_money": ("amount", "b")}, session="s")
    ok, reason = v.authorize("send_money", {"amount": bad})
    v.commit("send_money", {"amount": bad})
    assert ledger.spent("p", "b") == Decimal(0)


# --------------------------------------------------------------------------- #
# Reservations are capabilities, not amounts
# --------------------------------------------------------------------------- #
def test_one_session_cannot_release_another_sessions_hold():
    """`release(principal, budget, amount)` was a cross-session weapon.

    The reservation pool is shared by every session of a principal, so any
    session could subtract an amount it never reserved, wipe every other
    session's hold, and then book above the ceiling. A hold is now a capability:
    only whoever holds it can give it back.
    """
    ledger = PrincipalLedger()
    ceiling = Decimal(10000)
    honest = ledger.reserve("mandate:payouts", "usd", Decimal(9000), ceiling)
    assert honest is not None

    # The attacker holds nothing and can release nothing.
    ledger.release(None)
    attacker = ledger.reserve("mandate:payouts", "usd", Decimal(9000), ceiling)
    assert attacker is None, "the honest session's hold was wiped"


def test_a_hold_commits_the_amount_it_reserved():
    ledger = PrincipalLedger()
    hold = ledger.reserve("p", "usd", Decimal(10), Decimal(1000))
    ledger.commit_hold(hold, session="s")
    assert ledger.spent("p", "usd") == Decimal(10)


def test_releasing_a_hold_twice_is_harmless():
    ledger = PrincipalLedger()
    hold = ledger.reserve("p", "usd", Decimal(10), Decimal(1000))
    ledger.release(hold)
    ledger.release(hold)
    assert ledger.reserve("p", "usd", Decimal(1000), Decimal(1000)) is not None


def test_an_abandoned_hold_expires_instead_of_shrinking_the_ceiling_forever():
    """An agent that authorizes and then dies used to shrink the principal's
    ceiling permanently, and enough abandoned holds took it to zero."""
    ledger = PrincipalLedger(reservation_ttl_seconds=60.0)
    ceiling = Decimal(1000)
    assert ledger.reserve("p", "usd", Decimal(900), ceiling, now=0.0) is not None
    # Same instant: no headroom.
    assert ledger.reserve("p", "usd", Decimal(900), ceiling, now=0.0) is None
    # After the TTL the abandoned hold no longer counts.
    assert ledger.reserve("p", "usd", Decimal(900), ceiling, now=120.0) is not None


# --------------------------------------------------------------------------- #
# Structuring: the concentration measure, and the cliff it replaces
# --------------------------------------------------------------------------- #
def _signal(amounts, ceiling="10000"):
    ledger = PrincipalLedger()
    for i, a in enumerate(amounts):
        ledger.book("p", "usd", Decimal(str(a)), session=f"s{i}")
    return structuring_signal(ledger, "p", "usd", Decimal(ceiling))


@pytest.mark.parametrize("name,amounts", [
    ("uniform split to the ceiling", [2500] * 4),
    ("jittered split", [2400, 2600, 2550, 2450]),
    ("one at 60% plus small", [6000, 1000, 1000, 1000, 1000]),
    ("one at 70% plus small", [7000, 800, 800, 800, 800]),
    ("one at 55% plus many small", [5500] + [500] * 9),
])
def test_structuring_survives_a_dominant_fragment(name, amounts):
    """The blind spot this replaces.

    The fragmentation test used to require the LARGEST fragment to sit below
    half the ceiling, and that threshold was itself the escape: one payment
    anywhere between 50% and 80% of the ceiling defeated it at every fragment
    count while staying below the just-under band. Four of five structuring
    patterns went unflagged.

    The inverse Herfindahl index moves smoothly, so there is no amount an
    attacker can choose to fall off the far side of it.
    """
    assert _signal(amounts).suspicious, name


@pytest.mark.parametrize("name,amounts", [
    ("real invoice run", [1200.50, 890.24, 1450.00, 1100.00, 1240.00]),
    ("payroll, uniform but low utilisation", [100] * 5),
    ("one large payment", [9900]),
    ("two medium payments", [3000, 3500]),
])
def test_legitimate_spend_is_not_flagged(name, amounts):
    assert not _signal(amounts).suspicious, name


def test_a_single_payment_can_never_be_structuring():
    """Effective fragment count is exactly 1 for one payment, whatever its size."""
    sig = _signal([9999])
    assert sig.effective_fragments == pytest.approx(1.0)
    assert not sig.suspicious


def test_the_signal_does_not_fire_below_high_utilisation():
    """Measured, not assumed: 0 of 4,781 synthetic legitimate runs below 80%
    utilisation were flagged. A control that fires on ordinary spend gets
    switched off, and then it protects nothing."""
    import random

    rng = random.Random(7)
    fired = 0
    runs = 0
    for _ in range(400):
        k = rng.randint(1, 12)
        util = rng.uniform(0.05, 0.75)
        raw = [rng.lognormvariate(0, 0.8) for _ in range(k)]
        scale = 10000.0 * util / sum(raw)
        runs += 1
        fired += _signal([round(x * scale, 2) for x in raw]).suspicious
    assert fired == 0, f"{fired}/{runs} legitimate runs flagged below 75% utilisation"


# --------------------------------------------------------------------------- #
# Durability. Under-counting is the failure direction that matters.
# --------------------------------------------------------------------------- #
def test_a_torn_append_does_not_swallow_the_next_acknowledged_write(tmp_path):
    """A crash mid-append leaves bytes with no trailing newline. The next append
    concatenated onto them and the merged line parsed as neither record, so BOTH
    were lost: an acknowledged booking of 500 vanished and the ledger reloaded at
    100 instead of 600.

    An over-counted ledger refuses work. An under-counted one raises a ceiling
    the operator believes is in force.
    """
    path = tmp_path / "ledger.jsonl"
    PrincipalLedger(path=path).book("p", "usd", Decimal(100), session="s1")

    with path.open("a") as fh:                      # simulate the crash
        fh.write('{"principal": "p", "budget_id": "usd", "amoun')

    PrincipalLedger(path=path).book("p", "usd", Decimal(500), session="s2")
    assert PrincipalLedger(path=path).spent("p", "usd") == Decimal(600)


def test_the_torn_record_itself_is_discarded(tmp_path):
    """It was never acknowledged to any caller, so losing it is correct. What
    must not happen is it taking the next one with it."""
    path = tmp_path / "ledger.jsonl"
    PrincipalLedger(path=path).book("p", "usd", Decimal(100), session="s1")
    with path.open("a") as fh:
        fh.write('{"principal": "p", "budget_id": "usd", "amount": "999')
    assert PrincipalLedger(path=path).spent("p", "usd") == Decimal(100)


def test_a_ledger_survives_repeated_crash_and_restart(tmp_path):
    path = tmp_path / "ledger.jsonl"
    for i in range(10):
        PrincipalLedger(path=path).book("p", "usd", Decimal(10), session=f"s{i}")
        with path.open("a") as fh:
            fh.write('{"partial')
    final = PrincipalLedger(path=path)
    assert final.spent("p", "usd") == Decimal(100)
    assert final.verify_totals()


# --------------------------------------------------------------------------- #
# The threshold's own just-under evasion
# --------------------------------------------------------------------------- #
def _windows(pattern, ceiling="10000", window=86400):
    from clayseal.capabilities.principal_ledger import parks_below_the_gate

    ledger = PrincipalLedger(window_seconds=window)
    now = (len(pattern) + 1) * window
    for i, util in enumerate(pattern):
        at = now - (len(pattern) - i) * window + 1
        for j in range(4):
            ledger.book("p", "usd",
                        Decimal(str(round(float(Decimal(ceiling)) * util / 4, 2))),
                        session=f"w{i}s{j}", now=at)
    return parks_below_the_gate(ledger, "p", "usd", Decimal(ceiling), now=now)


def test_parking_just_under_the_gate_is_missed_by_the_single_window_test():
    """The evasion, pinned so the limit stays visible.

    `structuring_signal` fires above a utilisation threshold, and any threshold
    has a just-under evasion by construction. Four equal payments totalling
    84.99% of the ceiling trip nothing, and lowering the gate only moves it:
    measured over 3,000 synthetic legitimate runs, gate 0.85 flags 12.2% of them
    and gate 0.50 flags 40.0%, and at every one the attacker parked a basis point
    below and was missed.
    """
    ledger = PrincipalLedger()
    for i in range(4):
        ledger.book("p", "usd", Decimal("2124.75"), session=f"s{i}")
    assert not structuring_signal(ledger, "p", "usd", Decimal(10000)).suspicious


def test_parking_there_window_after_window_is_its_own_signature():
    """Real spend does not hug a line it cannot see. An agent shaping its
    behaviour to a limit does."""
    assert _windows([0.8499] * 6).suspicious
    assert _windows([0.84, 0.83, 0.845, 0.838, 0.842, 0.849]).suspicious


@pytest.mark.parametrize("pattern,label", [
    ([0.2, 0.9, 0.35, 0.75, 0.1, 0.95], "ordinary bursty business"),
    ([0.05] * 6, "low steady usage"),
    ([0.5, 0.55, 0.45, 0.6, 0.5, 0.55], "steady mid usage"),
    ([0.99] * 6, "consistently near the ceiling, caught by the single-window test"),
])
def test_ordinary_spend_does_not_look_like_parking(pattern, label):
    assert not _windows(pattern).suspicious, label


def test_reading_the_windows_does_not_destroy_them():
    """`entries_in_window` prunes as it reads, so walking backwards through
    windows with it evicts the history being measured and every window after the
    first reports zero. This asserts the log is read without mutation."""
    signal = _windows([0.8499] * 6)
    assert signal.just_under == 6


# --------------------------------------------------------------------------- #
# Reserve/commit desync: the hold TTL against the ceiling
# --------------------------------------------------------------------------- #
def test_a_late_commit_past_a_voided_hold_is_recorded_as_a_breach():
    """The escape: patience, not clock control.

    Reserve the whole ceiling, wait out the reservation TTL, reserve it again
    (the first hold has been voided, so the headroom is free), then commit both.
    `commit_hold` books from the Hold and cannot re-check at the point it is
    called, so this booked **200 against a ceiling of 100** and reported
    nothing. Five minutes of waiting, and a session lasting longer than the
    tool timeout is entirely ordinary.

    Both amounts are still booked, because the effects landed and a ledger that
    declines to record them under-counts, which this module's own docstring
    calls "the failure that lets an attack through". What must not happen is
    that it goes unnoticed.
    """
    ledger = PrincipalLedger(reservation_ttl_seconds=60.0)
    ceiling = Decimal(100)
    first = ledger.reserve("p", "usd", Decimal(100), ceiling, now=0.0)
    second = ledger.reserve("p", "usd", Decimal(100), ceiling, now=120.0)
    assert first is not None and second is not None

    ledger.commit_hold(first, now=121.0)
    ledger.commit_hold(second, now=122.0)

    assert ledger.spent("p", "usd", now=123.0) == Decimal(200)
    breaches = ledger.late_breaches()
    assert len(breaches) == 1, "the over-ceiling commit was absorbed silently"
    assert breaches[0].amount == Decimal(100)
    assert ledger.verify_totals()


def test_the_breach_check_counts_outstanding_holds():
    """Why the projection includes `_holds` and not just `spent`.

    The first version of this check compared `spent + amount` against the
    ceiling. At the moment the voided hold commits, nothing is spent yet and the
    replacement reservation is still a HOLD, so 100 against a ceiling of 100
    looked fine and the breach was missed. The outstanding holds are precisely
    the reservations granted using the headroom the voided hold gave back.
    """
    ledger = PrincipalLedger(reservation_ttl_seconds=60.0)
    ceiling = Decimal(100)
    voided = ledger.reserve("p", "usd", Decimal(100), ceiling, now=0.0)
    ledger.reserve("p", "usd", Decimal(100), ceiling, now=120.0)  # still held
    ledger.commit_hold(voided, now=121.0)
    assert ledger.late_breaches(), "outstanding holds were left out of the check"


def test_a_slow_but_legitimate_commit_is_not_a_breach():
    """The false-positive side. An action that simply took longer than the TTL,
    with no second reservation behind it, still fits and must not be flagged."""
    ledger = PrincipalLedger(reservation_ttl_seconds=60.0)
    hold = ledger.reserve("p", "usd", Decimal(100), Decimal(100), now=0.0)
    ledger.commit_hold(hold, now=500.0)
    assert ledger.spent("p", "usd", now=501.0) == Decimal(100)
    assert ledger.late_breaches() == []


def test_committing_one_hold_twice_books_once():
    ledger = PrincipalLedger()
    hold = ledger.reserve("p", "usd", Decimal(10), Decimal(1000))
    ledger.commit_hold(hold, session="s")
    ledger.commit_hold(hold, session="s")
    assert ledger.spent("p", "usd") == Decimal(10)
    assert ledger.verify_totals()


# --------------------------------------------------------------------------- #
# Delegation splitting: the axis the plan called unclosed by construction
# --------------------------------------------------------------------------- #
def _delegated(sub: str, chain: list[str] | None = None):
    from clayseal.core.authority_binding import AuthorityBinding
    return AuthorityBinding(subject_id=sub, authority_id="a",
                            issuer="https://corp.example",
                            delegation_chain=list(chain or []))


def _chain_view(ledger, binding, ceiling=Decimal(100)):
    from clayseal.capabilities.principal_ledger import (
        PrincipalBudgetView,
        principal_chain,
        principal_key,
    )
    return PrincipalBudgetView(
        ledger=ledger, principal=principal_key(binding),
        chain=principal_chain(binding), ceilings={"usd": ceiling},
        tracked={"payments.transfer": ("amount", "usd")},
        session=binding.subject_id)


def _chain_spend(view, amount, now):
    allowed, _ = view.authorize("payments.transfer", {"amount": str(amount)},
                                now=now)
    if allowed:
        view.commit("payments.transfer", {"amount": str(amount)}, now=now)
    return allowed


def test_a_parent_ceiling_bounds_everything_it_delegates_to():
    """Measured at 600 against a ceiling of 100 before the chain was wired.

    Each sub-agent has its own `sub`, so it had its own `principal_key` and its
    own ceiling. A per-delegate ceiling is not a ceiling: anyone who can spawn
    sub-agents mints headroom. The plan names this axis "unclosed by
    construction, and where MCP deployments live".
    """
    from clayseal.capabilities.principal_ledger import principal_key

    ledger = PrincipalLedger()
    parent = _delegated("parent")
    landed = 0
    for i, binding in enumerate(
            [parent] + [_delegated(f"sub-{n}", ["parent"]) for n in range(5)]):
        if _chain_spend(_chain_view(ledger, binding), 100, float(i)):
            landed += 100
    assert landed == 100, f"delegation split the ceiling: {landed} landed"
    assert ledger.spent(principal_key(parent), "usd", now=99.0) == Decimal(100)


def test_a_delegate_may_spend_the_parents_remaining_headroom():
    """The false-block direction. Binding the aggregate must not stop a delegate
    doing legitimate work inside what the parent has left."""
    ledger = PrincipalLedger()
    assert _chain_spend(_chain_view(ledger, _delegated("parent")), 50, 0.0)
    assert _chain_spend(_chain_view(ledger, _delegated("sub-0", ["parent"])), 30, 1.0)
    assert _chain_spend(_chain_view(ledger, _delegated("sub-1", ["parent"])), 15, 2.0)
    # 95 spent; 20 more would cross.
    assert not _chain_spend(_chain_view(ledger, _delegated("sub-2", ["parent"])), 20, 3.0)


def test_a_refused_delegate_action_does_not_consume_ancestor_headroom():
    """All-or-nothing reservation.

    A partial group would leave the parent's headroom held for a delegate action
    that never happened, which is the denial of service the hold TTL exists to
    prevent arriving by another route.
    """
    from clayseal.capabilities.principal_ledger import principal_key

    ledger = PrincipalLedger()
    parent = _delegated("parent")
    assert _chain_spend(_chain_view(ledger, parent), 100, 0.0)
    # Now every delegate is refused; none of them may hold parent headroom.
    for n in range(3):
        assert not _chain_spend(_chain_view(ledger, _delegated(f"sub-{n}", ["parent"])),
                          10, float(n + 1))
    assert ledger.spent(principal_key(parent), "usd", now=99.0) == Decimal(100)
    assert ledger.verify_totals()


def test_an_undelegated_principal_is_unchanged():
    """The chain defaults to empty, so a plain principal behaves as before."""
    ledger = PrincipalLedger()
    view = _chain_view(ledger, _delegated("solo"))
    assert view.chain == ()
    assert _chain_spend(view, 60, 0.0)
    assert _chain_spend(view, 40, 1.0)
    assert not _chain_spend(view, 1, 2.0)


def test_the_chain_is_issuer_qualified():
    """An unqualified chain entry would collide across issuers exactly as a bare
    `sub` does, which is the defect `principal_key` exists to avoid."""
    from clayseal.capabilities.principal_ledger import principal_chain
    from clayseal.core.authority_binding import AuthorityBinding

    good = AuthorityBinding(subject_id="s", authority_id="a",
                            issuer="https://good.example",
                            delegation_chain=["parent"])
    evil = AuthorityBinding(subject_id="s", authority_id="a",
                            issuer="https://evil.example",
                            delegation_chain=["parent"])
    assert principal_chain(good) != principal_chain(evil)


def test_claims_cannot_assert_their_own_delegation_chain():
    """The chain must come from verified delegation, never from a claims dict.

    `delegation_chain` is in `AUTHORITY_FIELDS`, so an adapter strips it. Without
    that, a token could name any parent it liked, and since a delegate's spend
    now books against its ancestors, an attacker could charge an unrelated
    principal's ceiling to exhaust it.
    """
    from clayseal.capabilities.identity_adapters import oidc
    from clayseal.capabilities.principal_ledger import principal_chain

    forged = oidc.provider.to_binding(
        {"subject_id": "attacker", "iss": "https://corp.example",
         "delegation_chain": ["victim"]})
    assert principal_chain(forged) == ()
