"""What a refusal code means, in a sentence someone can act on.

The README says to hand the refusal back to the agent. Handing back
``value_budget_exceeded`` tells it that something is wrong and nothing about
what to do instead, and that string is the most common refusal the gateway
emits: 49 of the 132 BPL scenarios end on it, with ``call_budget_exceeded``
next at 23. Most of the other codes already read as English
(``tool 'wire_funds' not granted``, ``egress to 'evil.test' not on allow-list``)
because they are built from the thing that failed. The budget codes are the
ones that are bare enums.

``Refused.reasons`` keeps the codes untouched. They are the stable, matchable
surface and tests and integrations depend on them. This module only affects what
``str(exc)`` says, which is the part a person reads and the part that gets
pasted into an agent's context.

A code with no entry here falls through to itself, so an unexplained code is
degraded output rather than a crash. `test_reason_explanations.py` asserts every
code the suite actually emits has an entry, so the fallback stays a safety net
rather than the normal case.
"""
from __future__ import annotations

#: code -> what happened, and what would change it.
#:
#: Written in the second person and ending in something to do. "Not permitted"
#: is not an explanation; "this session's ceiling is spent, start a new session
#: or raise the ceiling in the policy" is.
_EXPLANATIONS: dict[str, str] = {
    # ---- value budgets -----------------------------------------------------
    "value_budget_exceeded":
        "a spend ceiling for this session is used up, and this call would go "
        "over it. The ceiling covers the whole session, not one call, so "
        "individually reasonable amounts can add up to this. Raise it under "
        "`budgets.value.ceilings` in the policy, or start a new session.",
    "value_budget_negative_amount":
        "the amount on this call is negative. A negative spend would credit the "
        "ceiling back and let more through afterwards, so it is refused rather "
        "than booked. If this is a refund, give it its own budget rather than "
        "netting it against the one it is reversing.",
    "value_budget_unparseable_amount":
        "the amount on this call could not be read as money. Values like "
        "`1e999`, `Infinity`, `NaN`, an empty string, or an integer too large to "
        "express in cents all land here. The call is refused rather than "
        "treated as untracked, because a ceiling that stops applying exactly "
        "when the amount is absurd is worse than no ceiling.",
    "value_budget_duplicate_effect":
        "this looks like a repeat of an effect this session already booked, "
        "matched on its idempotency key. If it is a genuinely new one, give it "
        "a distinct `_idempotency_key`; if it is a retry of the same effect, it "
        "has already been counted and does not need to run again.",
    "value_budget_disabled_tightened":
        "the session is in tightened mode, where this budget is not available "
        "at all. Something earlier in the session triggered a conditional "
        "ceiling; look at the guard that fired rather than at this call.",

    # ---- call budgets ------------------------------------------------------
    "call_budget_exceeded":
        "this session has used its allowance of calls for this tool. The "
        "allowance covers the session, so a loop that retries will land here "
        "even when each attempt is individually fine. Raise it under "
        "`budgets.calls` in the policy, or start a new session.",
    "call_budget_duplicate_effect":
        "this call repeats one the session already counted, matched on its "
        "idempotency key. A retry of the same effect does not need to run "
        "again; a genuinely new one needs a distinct `_idempotency_key`.",
    "call_budget_disabled_tightened":
        "the session is in tightened mode and this tool is not callable in it. "
        "A conditional guard fired earlier in the session; that is what to look "
        "at, not this call.",
    "tool_call_budget_disabled_tightened":
        "the session is in tightened mode and this tool is not callable in it. "
        "A conditional guard fired earlier in the session; that is what to look "
        "at, not this call.",
    "target_call_budget_exhausted":
        "this session has used its allowance of calls against this particular "
        "target. The limit is per target rather than per tool, so other targets "
        "may still be reachable.",

    # ---- compute budgets ---------------------------------------------------
    "compute_budget_exhausted":
        "this session has used its compute allowance. Raise it in the policy, "
        "or start a new session.",
    "compute_budget_unusable_estimate":
        "the compute estimate for this call could not be read as a number, so "
        "it cannot be charged against the allowance and is refused rather than "
        "run uncounted.",

    # ---- scope and grant ---------------------------------------------------
    "value contains nothing attributable":
        "the destination on this call carries nothing that can be traced to "
        "the sealed goal or to an allow-listed value, so there is nothing to "
        "check it against. Name the destination in the goal, or add it to the "
        "egress allow-list.",
}


def explain(code: str) -> str:
    """A sentence for ``code``, or ``code`` itself if there is no entry.

    Falling through to the code is deliberate. A refusal that arrives with an
    unfamiliar code should still be readable as *something*, and a `KeyError`
    raised while building an error message would replace a refusal the caller
    can handle with a crash it cannot.
    """
    return _EXPLANATIONS.get(code, code)


def explained(reasons: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Every reason, explained where an explanation exists."""
    return tuple(explain(str(r)) for r in reasons)


def known_codes() -> frozenset[str]:
    """The codes this module can explain. For tests that assert coverage."""
    return frozenset(_EXPLANATIONS)
