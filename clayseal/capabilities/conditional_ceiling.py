"""Ceilings that depend on what has happened: "15,000, unless it is a rush job".

THE MISSING RUNG

Every budget in this layer carries a constant. Real authorities do not: a payout
limit collapses when the request is expedited, a trading limit tightens when a
position is already open, a retention window shortens once a hold notice
arrives. `benchmarks/bpl/scenarios` has these and the grants could not express
them, so `path-dependent-ceiling` reads *"rush collapses the ceiling"* and the
gateway was handed one number.

THE SAFETY PROPERTY, WHICH IS THE WHOLE DESIGN

A guard may only ever **tighten**. A guarded ceiling above the base one is refused
at construction.

That constraint is not conservatism, it is what makes the mechanism sound at all.
A condition is a fact about the session, and facts arrive from tool output, which
is content an attacker may control. If a guard could raise a ceiling, then
"expedited: false" injected into a document would widen authority, and the rung
would be a lever for the attacker rather than a control on them. Monotone
tightening removes that entirely: an attacker who fully controls every condition
can only reduce the authority available to the agent they have compromised.

The consequence is worth stating plainly, because it is a real limitation and not
a footnote. **A rule of the form "normally 5,000, and 15,000 once a manager
approves" cannot be written as a guard.** Raising authority is what step-up is
for: it requires a signed approval bound to the specific action, which is the only
thing that should be able to widen a grant. A guard and a step-up are the two
halves of "conditional", split by direction, and the split is the security
argument.

WHAT A GUARD READS

Named facts, recorded by the caller through `observe_fact`. The gateway feeds
these from the STRUCTURED fields of tool output, which is the same distinction
`ParameterProvenance` already draws between a value that arrived in a named field
of a trusted read and one that appeared in prose. Free text never becomes a fact.

Because tightening is monotone, an unknown or unevaluable condition is safe to
treat as matching, and it is: a guard whose fact has not been observed does not
fire, and a guard whose comparison raises fires. Fail closed in both directions
means "the tightest ceiling any guard could justify".
"""
from __future__ import annotations

import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from decimal import Decimal
from typing import Any

from clayseal.capabilities.value_budget import ValueBudgetConfig, _money


@dataclass(frozen=True)
class Guard:
    """One conditional tightening.

    `when` is a mapping of fact name to required value; every entry must match
    for the guard to fire. `ceilings` are the replacements, and each must be at
    or below the base for that budget id.
    """

    when: Mapping[str, Any]
    ceilings: Mapping[str, Any]
    reason: str = ""

    def matches(self, facts: Mapping[str, Any]) -> bool:
        for name, expected in self.when.items():
            if name not in facts:
                return False
            try:
                if not _equal(facts[name], expected):
                    return False
            except Exception:  # noqa: BLE001 - see the module docstring
                # A comparison that raises fires the guard. Tightening is
                # monotone, so the failure mode of "fire when unsure" is a
                # smaller ceiling, and there is no symmetric risk to weigh
                # against it.
                return True
        return True

    def describe(self) -> str:
        conditions = ", ".join(f"{k}={v!r}" for k, v in sorted(self.when.items()))
        limits = ", ".join(f"{k}<={v}" for k, v in sorted(self.ceilings.items()))
        return f"when {conditions}: {limits}" + (f"  ({self.reason})" if self.reason else "")


def _equal(observed: Any, expected: Any) -> bool:
    """Compare a fact to a guard's expectation without surprising coercions.

    Booleans are compared as booleans and not as numbers, because `1 == True` in
    Python and a fact of `1` matching a guard on `True` is the sort of accidental
    equality an authority decision must not rest on.
    """
    if isinstance(expected, bool) or isinstance(observed, bool):
        return bool(observed) is bool(expected) and \
            isinstance(observed, bool) == isinstance(expected, bool)
    if isinstance(expected, (int, float, Decimal)) and \
            isinstance(observed, (int, float, Decimal, str)):
        try:
            return _money(observed) == _money(expected)
        except Exception:  # noqa: BLE001, S110 - fall through to the string path
            pass
    return str(observed).strip().lower() == str(expected).strip().lower()


@dataclass
class GuardedCeilings(ValueBudgetConfig):
    """A `ValueBudgetConfig` whose ceilings tighten as facts arrive.

    Drops into any budget in this layer without changing it. `ceiling_for` is the
    single point at which every budget type reads a limit, so overriding it here
    covers the value, call and compute ledgers and composes with
    `WindowedValueBudget` for free.
    """

    guards: tuple[Guard, ...] = ()
    _facts: dict[str, Any] = field(default_factory=dict, repr=False)
    _flock: Any = field(default_factory=threading.RLock, repr=False, compare=False)

    def __post_init__(self) -> None:
        parent = getattr(super(), "__post_init__", None)
        if parent is not None:
            parent()
        for guard in self.guards:
            if not guard.when:
                raise ValueError(
                    "a guard with no condition applies always, which is a base "
                    "ceiling written in the wrong place"
                )
            for budget_id, value in guard.ceilings.items():
                base = self.ceilings.get(budget_id)
                if base is None:
                    raise ValueError(
                        f"guard tightens {budget_id!r}, which has no base "
                        f"ceiling; a conditional limit on nothing is not a control"
                    )
                if _money(value) > _money(base):
                    raise ValueError(
                        f"guard would RAISE {budget_id!r} from {base} to {value}. "
                        f"A guard may only tighten: a condition arrives as tool "
                        f"output, which an attacker may control, and a guard that "
                        f"can widen a grant is a lever for them rather than a "
                        f"control on them. Raising authority is what a signed "
                        f"step-up approval is for."
                    )

    # ------------------------------------------------------------------ #
    # Facts
    # ------------------------------------------------------------------ #
    def observe_fact(self, name: str, value: Any) -> None:
        """Record a fact a guard may read. Feed only STRUCTURED tool output."""
        with self._flock:
            self._facts[str(name)] = value

    def observe_facts(self, facts: Mapping[str, Any]) -> None:
        for name, value in (facts or {}).items():
            self.observe_fact(name, value)

    def facts(self) -> dict[str, Any]:
        with self._flock:
            return dict(self._facts)

    def fired(self) -> tuple[Guard, ...]:
        """Which guards currently apply. For a decision record."""
        with self._flock:
            snapshot = dict(self._facts)
        return tuple(g for g in self.guards if g.matches(snapshot))

    # ------------------------------------------------------------------ #
    # The one override
    # ------------------------------------------------------------------ #
    def ceiling_for(self, budget_id: str) -> Decimal | None:
        base = super().ceiling_for(budget_id)
        with self._flock:
            snapshot = dict(self._facts)
        tightest = base
        for guard in self.guards:
            candidate = guard.ceilings.get(budget_id)
            if candidate is None or not guard.matches(snapshot):
                continue
            value = _money(candidate)
            # `min` and not "last wins": two guards firing at once must give the
            # tightest of them, so the order they were declared in cannot change
            # an authority decision.
            tightest = value if tightest is None else min(tightest, value)
        return tightest

    def describe(self) -> str:
        lines = [f"base ceilings: {dict(self.ceilings)}"]
        active = self.fired()
        for guard in self.guards:
            mark = "ACTIVE" if guard in active else "      "
            lines.append(f"  {mark} {guard.describe()}")
        if active:
            effective = {b: str(self.ceiling_for(b)) for b in self.ceilings}
            lines.append(f"effective now: {effective}")
        return "\n".join(lines)


def guarded_from_config(
    config: ValueBudgetConfig, guards: tuple[Guard, ...] | list[Guard],
) -> GuardedCeilings:
    """Wrap an existing config's fields in a guarded one, unchanged otherwise."""
    fields = {f: getattr(config, f) for f in
              ("tracked", "ceilings", "supersession_eligible", "tightened")
              if hasattr(config, f)}
    return GuardedCeilings(**fields, guards=tuple(guards))


def tighten_in_place(config: ValueBudgetConfig, **ceilings: Any) -> ValueBudgetConfig:
    """A one-off tightening, for a caller that wants no guard machinery.

    Returns a NEW config: mutating a live one is how a ceiling changes under a
    reservation that has already been checked against the old value.
    """
    merged = dict(config.ceilings)
    for budget_id, value in ceilings.items():
        base = merged.get(budget_id)
        if base is not None and _money(value) > _money(base):
            raise ValueError(
                f"tighten_in_place would raise {budget_id!r} from {base} to "
                f"{value}; it only tightens"
            )
        merged[budget_id] = value
    return replace(config, ceilings=merged)


# --------------------------------------------------------------------------- #
# The same conditional, applied to which TOOLS are admissible rather than to
# how much they may spend.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ToolGuard:
    """One conditional withdrawal: when these facts hold, these tools are not.

    Measured on four `tau2-bench` policy documents, 469 lines of prose nobody
    here wrote, **31% of the rules that state a constraint are state-conditional
    prohibitions**: "an order can only be cancelled if its status is pending",
    "cabin cannot be changed if any flight has already been flown", "basic
    economy flights cannot be modified". A guarded CEILING cannot express any of
    them, because none of them is about an amount. That class was the second
    largest in the sample and was inexpressible.

    THE SAFETY ARGUMENT IS THE SAME ONE, AND IT HAS TO BE

    A guard may only ever WITHDRAW. The baseline is `tools.allow` and a guard
    subtracts from it, so an attacker who fully controls every fact can only
    reduce what the agent it has compromised may do. There is deliberately no
    form that ADMITS a tool when a fact holds, because facts arrive from tool
    output: an `admit-when` guard would let an injected `status: pending` widen
    a grant, which is precisely what `Guard` refuses to allow for ceilings.

    THE LIMITATION, STATED RATHER THAN BURIED

    "Only cancel if pending" is enforced here as "deny cancel when the status is
    known and is not pending". An adversary who controls the status field can
    therefore avoid the withdrawal and get the BASELINE authority, which is the
    authority they had anyway. So this rung binds drift and mistake, and it does
    not bind an adversary who owns the fact source. That is the same boundary
    the ceiling guards draw and it is worth naming twice.
    """

    when: Mapping[str, Any]
    deny: frozenset[str]
    reason: str = ""
    #: When true the condition is read as "unless": the tools are withdrawn
    #: whenever the facts do NOT match, which is how "only if" is written. An
    #: unknown fact then withdraws, because a precondition nobody has confirmed
    #: is not a precondition that has been met.
    unless: bool = False

    def withdraws(self, facts: Mapping[str, Any]) -> bool:
        matched = Guard(when=self.when, ceilings={}).matches(facts)
        if not self.unless:
            return matched
        # `unless`: withdraw when the condition is not confirmed. An absent fact
        # counts as unconfirmed, which withdraws, which is the safe direction.
        return not (matched and all(name in facts for name in self.when))


#: Facts the GATEWAY sets about its own decisions, never tool output. Prefixed
#: so the two sources cannot collide, and `observe_facts` refuses to write one:
#: without that refusal an ordering rule would be defeated by a tool returning
#: `{"called:get_order": true}`, which is the attacker asserting that a
#: precondition they never met has been met.
GATEWAY_FACT_PREFIX = "called:"


def called_fact(tool: str) -> str:
    return f"{GATEWAY_FACT_PREFIX}{tool}"


@dataclass
class ConditionalTools:
    """The admissible tool set as facts arrive. Only ever shrinks per fact set."""

    base: frozenset[str]
    guards: tuple[ToolGuard, ...] = ()
    _facts: dict[str, Any] = field(default_factory=dict)
    #: Tool output that tried to write a gateway fact. Non-zero means something
    #: attempted to assert a precondition it cannot know about.
    rejected_facts: int = 0

    def __post_init__(self) -> None:
        for guard in self.guards:
            unknown = set(guard.deny) - set(self.base)
            if unknown:
                raise ValueError(
                    f"tools.when withdraws {sorted(unknown)}, which "
                    f"tools.allow never granted. A guard subtracts from the "
                    f"grant and cannot reach outside it, so this rule would "
                    f"read as enforcement and do nothing."
                )

    def observe_facts(self, facts: Mapping[str, Any]) -> None:
        """Facts from tool OUTPUT, which an attacker may control.

        A gateway fact is refused here. An ordering rule reads "has this tool
        run yet", the gateway is the only thing that knows, and letting a tool
        result answer it would let an injected `{"called:get_order": true}`
        satisfy a precondition nobody met.
        """
        for name, value in facts.items():
            key = str(name)
            if key.startswith(GATEWAY_FACT_PREFIX):
                self.rejected_facts += 1
                continue
            self._facts[key] = value

    def record_call(self, tool: str) -> None:
        """The gateway allowed `tool`. Only the gateway may say so."""
        self._facts[called_fact(tool)] = True

    def withdrawn(self) -> frozenset[str]:
        out: set[str] = set()
        for guard in self.guards:
            try:
                fires = guard.withdraws(self._facts)
            except Exception:  # noqa: BLE001 - withdrawing is the safe direction
                fires = True
            if fires:
                out |= set(guard.deny)
        return frozenset(out)

    def reason_for(self, tool: str) -> str:
        """Why this tool is out of the grant, in the direction the rule reads.

        An `unless` guard withdraws when the condition is NOT met, so rendering
        it as "withdrawn while {status: pending}" states the opposite of the
        rule and would send an operator looking for the wrong thing.
        """
        for guard in self.guards:
            if tool in guard.deny and guard.withdraws(self._facts):
                if guard.reason:
                    return guard.reason
                condition = dict(guard.when)
                if guard.unless:
                    ordering = [k[len(GATEWAY_FACT_PREFIX):] for k in condition
                                if k.startswith(GATEWAY_FACT_PREFIX)]
                    if ordering:
                        return (f"{', '.join(sorted(ordering))} has not run yet "
                                f"in this session")
                    return f"withdrawn unless {condition}"
                return f"withdrawn while {condition}"
        return "withdrawn by a conditional rule"

    def allows(self, tool: str) -> bool:
        return tool in self.base and tool not in self.withdrawn()


def tool_guards_from_config(raw: Any, allowed: Iterable[str]) -> ConditionalTools:
    """Compile `tools.when` into a `ConditionalTools`. Refuses rather than guesses."""
    base = frozenset(str(t) for t in allowed or ())
    if raw is None:
        return ConditionalTools(base=base)
    if not isinstance(raw, list):
        # ValueError, not TypeError: every refusal in the policy compiler is a
        # ValueError so one `except` at the call site catches the lot.
        raise ValueError(  # noqa: TRY004
            "tools.when must be a list of {if: {...}, deny: [...]}")
    guards: list[ToolGuard] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(f"tools.when[{i}] must be a mapping")  # noqa: TRY004
        # `requires` is ordering, written as the withdrawal it already is:
        # a tool is out of the grant until its prerequisites have run. Measured
        # on four tau2-bench policy documents, ordering and positive obligation
        # is 36% of the rules that state a constraint, the largest single class,
        # and "the agent must first obtain the user id and reservation id" is
        # its typical form. The facts it reads are set by the gateway on its own
        # ALLOW decisions, so unlike a status field they are not something a
        # tool result can assert.
        requires = entry.get("requires")
        if requires is not None:
            if not isinstance(requires, list) or not requires:
                raise ValueError(
                    f"tools.when[{i}].requires must be a non-empty list of "
                    f"tools that have to run first")
            entry = {**entry,
                     "unless": {called_fact(str(t)): True for t in requires}}
        condition = entry.get("if") or entry.get("unless")
        if not isinstance(condition, dict) or not condition:
            raise ValueError(
                f"tools.when[{i}] needs a non-empty `if` or `unless` mapping of "
                f"fact name to required value")
        deny = entry.get("deny")
        if not isinstance(deny, list) or not deny:
            raise ValueError(
                f"tools.when[{i}] needs a non-empty `deny` list. A guard "
                f"withdraws tools and there is no admitting form, because a "
                f"fact an attacker can assert must never widen a grant.")
        guards.append(ToolGuard(
            when={str(k): v for k, v in condition.items()},
            deny=frozenset(str(t) for t in deny),
            reason=str(entry.get("reason", "")),
            unless="unless" in entry))
    return ConditionalTools(base=base, guards=tuple(guards))
