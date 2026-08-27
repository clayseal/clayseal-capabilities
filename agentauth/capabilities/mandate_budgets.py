"""Fail-closed dispatch from a signed mandate's budget section to the stateful
session enforcers.

A mandate can carry several budget *kinds* at once (a USD ceiling and a tool-call
allowance, say). Each kind has a different enforcer and different arithmetic:
money is summed at cent precision, calls are counted as integers. The bug this
module exists to prevent is routing one kind through the other's ledger, a
"3 tool calls" grant reinterpreted as a "$3.00" ceiling that nothing debits, so
an unlimited number of individually-valid calls sails through.

:func:`session_budgets_from_mandate` partitions the mandate's budgets by
``budget_type``, builds the matching enforcer for each kind it understands, and
**raises** on any kind it has no enforcer for. It never silently drops a limit:
a budget the caller signed is either enforced or the build fails.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from agentauth.capabilities.budget import (
    BudgetType,
    budget_type_of,
)
from agentauth.capabilities.budget import (
    budget_attr as _budget_attr,
)
from agentauth.capabilities.call_budget import (
    SessionCallBudget,
    session_call_budget_from_mandate,
)
from agentauth.capabilities.compute_budget import (
    SessionComputeBudget,
    session_compute_budget_from_mandate,
)
from agentauth.capabilities.value_budget import (
    SessionValueBudget,
    session_value_budget_from_mandate,
)

# Budget kinds that currently have a stateful session enforcer. Kinds outside
# this set are refused rather than approximated, see the module docstring.
#
# COMPUTE_SECONDS joined this set only once a sandboxed run could enforce it:
# the reservation is the timeout that kills the guest, so the ceiling is real
# rather than merely recorded. DATA_EXPORT_BYTES is deliberately still absent
# iVisor's verdict stream reports which destinations were reached, not how many
# bytes crossed, and charging a byte budget from anything else would be a
# fabricated measurement. It stays refused until something can honestly meter it.
SUPPORTED_BUDGET_TYPES = frozenset({
    BudgetType.USD_LIMIT,
    BudgetType.TOOL_CALL_LIMIT,
    BudgetType.COMPUTE_SECONDS,
})


class UnsupportedBudgetType(ValueError):
    """Raised when a mandate carries a budget kind with no session enforcer.

    Failing closed is deliberate: an authorization that grants, e.g., a token or
    compute-seconds budget must not be admitted as if that limit did not exist.
    """


@dataclass
class MandateBudgets:
    """The stateful enforcers hydrated from one mandate. Either may be ``None``
    if the mandate carried no budget of that kind."""

    value: SessionValueBudget | None = None
    calls: SessionCallBudget | None = None
    compute: SessionComputeBudget | None = None


def session_budgets_from_mandate(
    mandate: Any,
    *,
    value_tracked: Mapping[str, tuple[str, str]] | None = None,
    call_tracked: Mapping[str, str] | None = None,
    compute_tracked: Mapping[str, str] | None = None,
    value_supersession_eligible: frozenset[str] | set[str] | None = None,
    call_supersession_eligible: frozenset[str] | set[str] | None = None,
    tightened: bool = False,
    allow_unsupported: bool = False,
) -> MandateBudgets:
    """Build every stateful session budget a mandate authorizes.

    ``value_tracked`` maps a tool to ``(arg_name, budget_id)`` for money budgets;
    ``call_tracked`` maps a tool to ``budget_id`` for call-count budgets;
    ``compute_tracked`` maps a tool to ``budget_id`` for compute-seconds budgets.
    Each is only required if the mandate actually carries that kind of budget.

    Raises :class:`UnsupportedBudgetType` if the mandate carries a budget kind
    with no enforcer, unless ``allow_unsupported`` is set (in which case such
    budgets are ignored, opt in only when a higher layer enforces them).
    """
    budgets = _budget_attr(mandate, "budgets") or []
    present = {budget_type_of(b) for b in budgets}

    unsupported = present - SUPPORTED_BUDGET_TYPES
    if unsupported and not allow_unsupported:
        names = ", ".join(sorted(t.value for t in unsupported))
        raise UnsupportedBudgetType(
            f"mandate carries budget type(s) with no session enforcer: {names}. "
            f"Refusing to admit the authorization rather than drop the limit "
            f"(pass allow_unsupported=True only if another layer enforces them)."
        )

    value = None
    if BudgetType.USD_LIMIT in present:
        if value_tracked is None:
            raise ValueError("mandate has a USD_LIMIT budget but value_tracked is None")
        value = session_value_budget_from_mandate(
            mandate,
            tracked=value_tracked,
            supersession_eligible=value_supersession_eligible,
            tightened=tightened,
        )

    calls = None
    if BudgetType.TOOL_CALL_LIMIT in present:
        if call_tracked is None:
            raise ValueError(
                "mandate has a TOOL_CALL_LIMIT budget but call_tracked is None"
            )
        calls = session_call_budget_from_mandate(
            mandate,
            tracked=call_tracked,
            supersession_eligible=call_supersession_eligible,
            tightened=tightened,
        )

    compute = None
    if BudgetType.COMPUTE_SECONDS in present:
        if compute_tracked is None:
            raise ValueError(
                "mandate has a COMPUTE_SECONDS budget but compute_tracked is None"
            )
        compute = session_compute_budget_from_mandate(
            mandate,
            tracked=compute_tracked,
            tightened=tightened,
        )

    return MandateBudgets(value=value, calls=calls, compute=compute)
