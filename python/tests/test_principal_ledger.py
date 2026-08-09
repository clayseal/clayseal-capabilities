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


def test_totals_are_derived_from_entries_not_cached():
    """A cached total beside the log can drift from it. Deriving is slower and
    means a lost write cannot silently raise a ceiling."""
    ledger = PrincipalLedger()
    ledger.book("p", "usd_payout", Decimal("100"))
    ledger._entries.clear()
    assert ledger.spent("p", "usd_payout") == Decimal("0")


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
