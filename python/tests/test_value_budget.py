from __future__ import annotations

import threading
from decimal import Decimal

from agentauth.capabilities.value_budget import SessionValueBudget, ValueBudgetConfig

_TRACKED = {
    "issue_payroll_bonus": ("bonus_amount", "usd_payout"),
    "legacy_process_bonus_payment": ("amount", "usd_payout"),
}


def _budget(ceiling: float = 20000.0, *, supersession: bool = True) -> SessionValueBudget:
    return SessionValueBudget(
        config=ValueBudgetConfig(
            tracked=dict(_TRACKED),
            ceilings={"usd_payout": ceiling},
            supersession_eligible=(
                frozenset(_TRACKED) if supersession else frozenset()
            ),
        )
    )


def test_cumulative_sum_blocks_at_ceiling():
    b = _budget(20000.0)
    # Four $5000 payouts to four targets fit; the fifth crosses $20k.
    for _ in range(4):
        allowed, _ = b.would_allow("issue_payroll_bonus", {"bonus_amount": 5000.0})
        assert allowed
        b.commit("issue_payroll_bonus", {"bonus_amount": 5000.0})
    allowed, reason = b.would_allow("issue_payroll_bonus", {"bonus_amount": 5000.0})
    assert not allowed and reason == "value_budget_exceeded"


def test_large_single_under_ceiling_allowed():
    b = _budget(20000.0)
    allowed, _ = b.would_allow("issue_payroll_bonus", {"bonus_amount": 18000.0})
    assert allowed


def test_tool_agnostic_shared_budget():
    """The governed tool and the legacy connector debit the SAME budget --
    the ceiling can't be evaded by switching tools."""
    b = _budget(20000.0)
    b.commit("issue_payroll_bonus", {"bonus_amount": 15000.0})
    # Only $5k of headroom left, on the *other* tool.
    allowed, _ = b.would_allow("legacy_process_bonus_payment", {"amount": 4000.0})
    assert allowed
    blocked, reason = b.would_allow("legacy_process_bonus_payment", {"amount": 6000.0})
    assert not blocked and reason == "value_budget_exceeded"


def test_untracked_tool_and_no_ceiling_pass():
    b = _budget(20000.0)
    allowed, reason = b.would_allow("update_job_title", {"new_title": "Staff"})
    assert allowed and reason == "ok_untracked"


def test_supersession_nets_down_never_accumulates():
    """The core safety property: a same-key correction REPLACES, so it can
    only ever reduce a total -- never accumulate. $8000 then a $7000 same-key
    correction nets to $7000, not $15000."""
    b = _budget(20000.0)
    args1 = {"bonus_amount": 8000.0, "_idempotency_key": "k"}
    args2 = {"bonus_amount": 7000.0, "_idempotency_key": "k"}
    b.commit("issue_payroll_bonus", args1)
    assert b.spent["usd_payout"] == 8000.0
    allowed, reason = b.would_allow("issue_payroll_bonus", args2)
    assert allowed and reason == "ok"
    b.commit("issue_payroll_bonus", args2)
    assert b.spent["usd_payout"] == 7000.0  # replaced, not summed


def test_supersession_cannot_be_used_to_exceed_ceiling():
    """Even abusing a shared key, an attacker can't push cumulative over the
    ceiling: a same-key call is measured as (spent - prior + new)."""
    b = _budget(10000.0)
    b.commit("issue_payroll_bonus", {"bonus_amount": 9000.0, "_idempotency_key": "k"})
    # A same-key 'correction' to $9500 is fine (net 9500 < 10000)...
    ok, _ = b.would_allow("issue_payroll_bonus", {"bonus_amount": 9500.0, "_idempotency_key": "k"})
    assert ok
    # ...but a same-key jump to $12000 still exceeds.
    bad, reason = b.would_allow(
        "issue_payroll_bonus", {"bonus_amount": 12000.0, "_idempotency_key": "k"}
    )
    assert not bad and reason == "value_budget_exceeded"


def test_distinct_keys_still_accumulate():
    """Two DIFFERENT keys are two distinct effects -- they sum (this is what
    keeps a fragmented attack from hiding behind supersession)."""
    b = _budget(10000.0)
    b.commit("issue_payroll_bonus", {"bonus_amount": 6000.0, "_idempotency_key": "a"})
    blocked, reason = b.would_allow(
        "issue_payroll_bonus", {"bonus_amount": 6000.0, "_idempotency_key": "b"}
    )
    assert not blocked and reason == "value_budget_exceeded"


def test_supersession_ignored_when_tool_not_eligible():
    b = _budget(20000.0, supersession=False)
    args = {"bonus_amount": 8000.0, "_idempotency_key": "k"}
    b.commit("issue_payroll_bonus", args)
    b.commit("issue_payroll_bonus", {"bonus_amount": 7000.0, "_idempotency_key": "k"})
    # Not eligible -> the key is ignored, so it accumulates.
    assert b.spent["usd_payout"] == 15000.0


def test_money_uses_decimal_not_float():
    """Three $0.10 payments sum to EXACTLY $0.30 -- with binary floats
    0.1+0.1+0.1 = 0.30000000000000004 would wrongly trip a $0.30 ceiling."""
    b = SessionValueBudget(
        config=ValueBudgetConfig(
            tracked={"pay": ("amt", "cents")}, ceilings={"cents": "0.30"}
        )
    )
    for _ in range(2):
        assert b.would_allow("pay", {"amt": 0.10})[0]
        b.commit("pay", {"amt": 0.10})
    allowed, _ = b.would_allow("pay", {"amt": 0.10})  # third fits exactly
    assert allowed
    b.commit("pay", {"amt": 0.10})
    assert b.spent["cents"] == Decimal("0.30")
    assert not b.would_allow("pay", {"amt": 0.01})[0]


def test_reserve_is_atomic_gate_and_release_restores():
    b = _budget(20000.0)
    r1 = b.reserve("issue_payroll_bonus", {"bonus_amount": 15000.0})
    assert r1.allowed
    # Reservation counts against the ceiling even before commit.
    r2 = b.reserve("issue_payroll_bonus", {"bonus_amount": 6000.0})
    assert not r2.allowed and r2.reason == "value_budget_exceeded"
    # Rolling back the first reservation frees the headroom again.
    r1.release()
    r3 = b.reserve("issue_payroll_bonus", {"bonus_amount": 6000.0})
    assert r3.allowed
    r3.commit()
    assert b.spent["usd_payout"] == Decimal("6000.00")


def test_parallel_reserve_cannot_exceed_ceiling():
    """The TOCTOU fix: N concurrent reservations of $100 against a $1000 ceiling
    let exactly 10 through, no matter the interleaving."""
    b = _budget(1000.0)
    results: list[bool] = []
    lock = threading.Lock()
    barrier = threading.Barrier(50)

    def worker():
        barrier.wait()
        r = b.reserve("issue_payroll_bonus", {"bonus_amount": 100.0})
        with lock:
            results.append(r.allowed)

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 10


def test_negative_amount_cannot_open_ceiling_headroom():
    """A negative debit must be rejected: otherwise booking -X drops the running total
    and lets a later call exceed the ceiling by X (a ceiling bypass)."""
    cfg = ValueBudgetConfig(
        tracked=dict(_TRACKED), ceilings={"usd_payout": "1000"},
        supersession_eligible=frozenset({"issue_payroll_bonus"}),
    )
    b = SessionValueBudget(config=cfg)
    # negative is rejected at every gate
    assert b.would_allow("issue_payroll_bonus", {"bonus_amount": -1_000_000})[0] is False
    assert b.reserve("issue_payroll_bonus", {"bonus_amount": -1_000_000}).allowed is False
    b.commit("issue_payroll_bonus", {"bonus_amount": -1_000_000})  # must not book
    assert b.spent.get("usd_payout", Decimal(0)) == Decimal(0)
    # ...so the ceiling still holds for a subsequent large payout
    assert b.reserve("issue_payroll_bonus", {"bonus_amount": 5000}).allowed is False


def test_supersession_reduction_still_allowed():
    """A same-idempotency-key replace that lowers the amount (negative NET of two
    positive amounts) must still be allowed — the guard is on the raw amount, not net."""
    cfg = ValueBudgetConfig(
        tracked=dict(_TRACKED), ceilings={"usd_payout": "1000"},
        supersession_eligible=frozenset({"issue_payroll_bonus"}),
    )
    b = SessionValueBudget(config=cfg)
    r = b.reserve("issue_payroll_bonus", {"bonus_amount": 800, "_idempotency_key": "k1"})
    assert r.allowed
    r.commit()
    lowered = b.reserve("issue_payroll_bonus", {"bonus_amount": 300, "_idempotency_key": "k1"})
    assert lowered.allowed is True
