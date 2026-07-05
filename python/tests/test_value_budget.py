from __future__ import annotations

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
