from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from agentauth.capabilities.budget import BudgetType, CapabilityBudget
from agentauth.capabilities.mandate import Mandate
from agentauth.capabilities.value_budget import (
    SessionValueBudget,
    ValueBudgetConfig,
    session_value_budget_from_mandate,
)

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
    positive amounts) must still be allowed, the guard is on the raw amount, not net."""
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


def test_mandate_budget_blocks_fragmented_payments():
    """A signed mandate/IFS-style capability is not enough by itself: each $999
    payment is individually below a $1000 grant, but the live L2 ledger must
    reject the second effect because the session total would be $1998."""
    now = datetime.now(timezone.utc)
    mandate = Mandate(
        grant_id="grant-payroll-001",
        issuer="security-team",
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
        allowed_actions=["issue_payroll_bonus", "legacy_process_bonus_payment"],
        budgets=[
            CapabilityBudget(
                budget_id="usd_payout",
                budget_type=BudgetType.USD_LIMIT,
                unit="USD",
                limit=1000,
                remaining=1000,
                shared=True,
            )
        ],
    )
    b = session_value_budget_from_mandate(mandate, tracked=_TRACKED)

    first = b.reserve("issue_payroll_bonus", {"bonus_amount": 999})
    assert first.allowed
    first.commit()

    second = b.reserve("legacy_process_bonus_payment", {"amount": 999})
    assert not second.allowed
    assert second.reason == "value_budget_exceeded"
    assert b.spent["usd_payout"] == Decimal("999.00")


def test_mandate_budget_uses_remaining_when_lower_than_limit():
    now = datetime.now(timezone.utc)
    mandate = Mandate(
        grant_id="grant-payroll-partial",
        issuer="security-team",
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
        budgets=[
            CapabilityBudget(
                budget_id="usd_payout",
                budget_type=BudgetType.USD_LIMIT,
                unit="USD",
                limit=1000,
                remaining=500,
            )
        ],
    )
    b = session_value_budget_from_mandate(mandate, tracked=_TRACKED)

    assert b.reserve("issue_payroll_bonus", {"bonus_amount": 500}).allowed
    blocked = b.reserve("issue_payroll_bonus", {"bonus_amount": 501})
    assert not blocked.allowed
    assert blocked.reason == "value_budget_exceeded"


def test_value_helper_ignores_non_usd_budgets():
    """Regression: the value ledger is money-only. A TOOL_CALL_LIMIT grant must
    NOT be coerced into a dollar ceiling here (the prior bug turned '3 calls'
    into a phantom '$3.00' ceiling that nothing ever debited)."""
    now = datetime.now(timezone.utc)
    mandate = Mandate(
        grant_id="g-mixed",
        issuer="security-team",
        issued_at=now,
        expires_at=now + timedelta(minutes=15),
        budgets=[
            CapabilityBudget(
                budget_id="usd_payout",
                budget_type=BudgetType.USD_LIMIT,
                unit="USD",
                limit=1000,
                remaining=1000,
            ),
            CapabilityBudget(
                budget_id="calls",
                budget_type=BudgetType.TOOL_CALL_LIMIT,
                unit="calls",
                limit=3,
                remaining=3,
            ),
        ],
    )
    b = session_value_budget_from_mandate(mandate, tracked=_TRACKED)
    assert b.config.ceilings == {"usd_payout": "1000.00"}  # only the USD budget
    assert "calls" not in b.config.ceilings


# --------------------------------------------------------------------------- #
# Once-per-object: a predicate the value ceiling structurally cannot express
# --------------------------------------------------------------------------- #
def _identity_budget(ceiling="5000"):
    from agentauth.capabilities.value_budget import EffectSpec

    return SessionValueBudget(config=ValueBudgetConfig(
        tracked={"pay_invoice": EffectSpec(
            budget_id="usd", amount_arg="amount", identity_args=("invoice",))},
        ceilings={"usd": Decimal(ceiling)}))


def _pay(budget, invoice, amount="1200"):
    res = budget.reserve("pay_invoice", {"invoice": invoice, "amount": amount})
    if res.allowed:
        res.commit()
    return res


def test_the_same_object_cannot_receive_the_effect_twice():
    """`retry-storm-double-effect`: three correct answers to the wrong question.

    Paying INV-1 twice at 1200 against a ceiling with room for 3600 is under the
    ceiling on every call, and the invoice is still paid twice. The ledger was
    asked "is the total under the limit" and answered correctly. The scenario's
    own goal says "Pay each invoice once under ceiling", and a mandate had no
    way to write the first half of that sentence down.
    """
    budget = _identity_budget()
    assert _pay(budget, "INV-1").allowed
    second = _pay(budget, "INV-1")
    assert not second.allowed
    assert second.reason == "value_budget_duplicate_effect"


def test_a_different_object_is_unaffected():
    budget = _identity_budget()
    assert _pay(budget, "INV-1").allowed
    assert _pay(budget, "INV-2").allowed
    assert _pay(budget, "INV-3").allowed


def test_the_ceiling_still_applies_alongside_identity():
    """Both predicates hold at once; neither replaces the other."""
    budget = _identity_budget(ceiling="2000")
    assert _pay(budget, "INV-1").allowed
    over = _pay(budget, "INV-2")
    assert not over.allowed
    assert over.reason == "value_budget_exceeded"


def test_a_released_reservation_frees_its_object():
    """The failure that would hide, because it is safe.

    Without this a downstream refusal pins the identity for the whole session,
    and the retry of a legitimate action is refused as a duplicate.
    """
    budget = _identity_budget()
    res = budget.reserve("pay_invoice", {"invoice": "INV-1", "amount": "1200"})
    assert res.allowed
    res.release()
    assert _pay(budget, "INV-1").allowed


def test_an_omitted_identity_field_does_not_mint_a_fresh_object():
    """Two calls differing only in which identity field is absent must not
    collapse to one key, or an attacker omits the field to get a new identity."""
    budget = _identity_budget()
    first = budget.reserve("pay_invoice", {"amount": "1200"})
    assert first.allowed
    first.commit()
    second = budget.reserve("pay_invoice", {"amount": "1200"})
    assert not second.allowed


def test_a_mandate_without_identity_args_behaves_exactly_as_before():
    """Backward compatible: the legacy tuple form is unchanged."""
    budget = SessionValueBudget(config=ValueBudgetConfig(
        tracked={"pay_invoice": ("amount", "usd")},
        ceilings={"usd": Decimal(5000)}))
    assert _pay(budget, "INV-1").allowed
    assert _pay(budget, "INV-1").allowed          # duplicates allowed, as before
