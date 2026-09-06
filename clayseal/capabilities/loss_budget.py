"""Select compiled rules under a relative loss budget.

THE PRODUCTION INPUT
--------------------
An operator can state how much of their own known-good traffic they are
willing to lose. That number is a fraction of actions, not a count of
confirmations: 0.02 means two in a hundred of the actions a correct agent
already produces may be refused.

WHY THIS IS COMPILE-TIME ONLY
-----------------------------
A running budget at decision time is an attack. An adversary issues
lookalike-benign calls until the remaining allowance is spent, then the
attack. So the budget is applied once, against logs the operator trusts,
and the resulting rule set is frozen. Decision time has no leftover to spend.

RELATION TO REFUTATION
----------------------
`relative_loss=0` is the existing refutation: any rule that fires on
known-good traffic is dropped. A non-zero budget keeps rules whose UNION
refusal rate on those logs stays at or under the number. Mandate-stated
constraints (ceilings, allow-lists, structured intent) are never in this
selection; they are authority, not inference.

A rule is tested ALONE before it is considered for the set. Testing only
the set would let one rule's refusal mask another's, which is how a bad
entity list survived the first refutation: it was never evaluated against
arguments. The union measurement then decides whether the survivors FIT.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

__all__ = ["select_under_budget", "union_loss"]

#: Kinds the four goal ledgers know how to enforce. Identity flags are not
#: selected here: `refuted_by_traffic` never dropped them, and changing that
#: silently would retune a measured arm.
_SELECTABLE = ("precedence", "invalidations", "entities")


def _as_trace(traces: Iterable[Any]) -> list[tuple[str, Any]]:
    """Accept one trace of (tool, args), or a list of such traces."""
    rows = list(traces or ())
    if not rows:
        return []
    first = rows[0]
    if isinstance(first, (list, tuple)) and first and not isinstance(first[0], str):
        out: list[tuple[str, Any]] = []
        for trace in rows:
            out.extend((str(t), a) for t, a in trace)
        return out
    return [(str(t), a) for t, a in rows]


def union_loss(compiled: Mapping[str, Any] | None, traces: Iterable[Any],
               clause: str = "") -> float:
    """Fraction of known-good actions the compiled set refuses.

    Replays in order and observes on the allow path only, which is the
    gateway's own discipline: a refused call never establishes state a later
    call reads. Empty traffic is a measurement that cannot be taken, not a
    zero, and the caller has to decide what that means.
    """
    from clayseal.capabilities.derivation import (
        _CHECK,
        _LEDGER_OF,
        _OBSERVE,
        _verb,
        rungs_from_compiled,
    )

    steps = _as_trace(traces)
    if not steps or not compiled:
        return 0.0
    ledgers = rungs_from_compiled(dict(compiled), clause)
    refused = 0
    for tool, args in steps:
        verb = _verb(tool)
        hit = False
        for kind in _SELECTABLE:
            led = ledgers.get(_LEDGER_OF[kind])
            if led is None:
                continue
            result = _CHECK[kind](led, tool, verb, args)
            ok = bool(result[0]) if isinstance(result, tuple) else bool(result)
            if not ok:
                hit = True
                break
        if hit:
            refused += 1
            continue
        for kind in _SELECTABLE:
            led = ledgers.get(_LEDGER_OF[kind])
            if led is not None:
                _OBSERVE[kind](led, tool, verb, args)
    return refused / len(steps)


def _alone(kind: str, rule: Any, traces: Iterable[Any], clause: str) -> float:
    from clayseal.capabilities.derivation import _EMPTY

    one = {**_EMPTY, kind: [rule]}
    if kind in ("distinct_subjects", "idempotency"):
        one = {**_EMPTY, kind: rule}
    return union_loss(one, traces, clause)


def _rebuild(base: Mapping[str, Any],
             chosen: dict[str, list[Any]]) -> dict[str, Any]:
    out = dict(base)
    for kind in _SELECTABLE:
        out[kind] = list(chosen.get(kind) or [])
    return out


def select_under_budget(
    compiled: Mapping[str, Any] | None,
    traces: Iterable[Any],
    relative: float,
    *,
    clause: str = "",
) -> dict[str, Any] | None:
    """Largest subset of `compiled` whose union loss on `traces` is ≤ `relative`.

    `relative` is a fraction in ``[0, 1]``. Zero is full refutation. Mandate
    fields that are not inferred (the identity flags, anything the caller did
    not put in `_SELECTABLE`) pass through unchanged.

    Requires `traces`. A budget with nothing to measure against cannot be
    enforced and would be decorative, which is the failure a policy document
    exists to make visible.
    """
    if compiled is None:
        return None
    if relative < 0.0 or relative > 1.0:
        raise ValueError(
            f"relative_loss must be a fraction in [0, 1], not {relative!r}"
        )
    steps = _as_trace(traces)
    if not steps:
        raise ValueError(
            "relative_loss is a measurement and needs known-good traces. "
            "A budget with nothing to measure against cannot be enforced."
        )

    ranked: list[tuple[float, str, Any]] = []
    for kind in _SELECTABLE:
        for rule in compiled.get(kind) or []:
            ranked.append((_alone(kind, rule, steps, clause), kind, rule))
    # Cheap rules first, so a zero-loss constraint is never crowded out by a
    # spendier one that happened to be listed earlier.
    ranked.sort(key=lambda row: (row[0], row[1]))

    chosen: dict[str, list[Any]] = {kind: [] for kind in _SELECTABLE}
    for alone, kind, rule in ranked:
        if alone > relative:
            continue
        trial = {k: list(chosen[k]) for k in _SELECTABLE}
        trial[kind].append(rule)
        trial_map = _rebuild(compiled, trial)
        if union_loss(trial_map, steps, clause) <= relative:
            chosen[kind].append(rule)
    return _rebuild(compiled, chosen)
