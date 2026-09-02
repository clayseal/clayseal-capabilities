"""Which tool debits which ceiling, derived instead of typed.

`policy_scaffold.tracked_block` renders this section commented out and says why:

    The catalog knows which argument carries the amount and the document knows
    what the ceilings are; which tool debits which ceiling is in neither, and it
    is the decision the whole aggregate rung rests on.

That was true of the two halves taken separately, and it left the one manual step
on the path a whole rung rests on. Where a grant configures a budget this gateway
contains 83.3% of attacks; where it does not, 18.9%. Across 520 tasks from
external corpora, none configure one. The mapping is the deployment gap.

## The decision is smaller than it looks

Writing `tracked` by hand feels like an N-tools-by-M-ceilings assignment. It
almost never is. Across every scenario in this suite that budgets value at all,
**there is exactly one ceiling** (34 of 34). The operator is not choosing which
limit a tool debits; they are restating which of their tools spend, a fact the
schema already carries in the shape of an argument.

So the tiers below are ordered by how much is actually being decided:

    sole      one ceiling in the grant. Every tool that carries a quantity and
              does something with it debits the only limit there is. Nothing is
              being chosen, so nothing is being guessed.
    lexical   several ceilings. The ceiling's id and the sentence it was read
              out of are matched against the tool's name and the server's own
              description of it, by the same token comparison the precedence and
              freshness rungs use.
    proposed  the remainder, handed to a caller-supplied reader. Optional, never
              imported here, never reached at decision time.

## Monotone, because the catalogue is not trusted

`policy_scaffold` states the rule this module inherits: the thing describing the
tools is the thing being constrained. A derived binding may only ADD a debit. It
never removes one an operator wrote, never redirects one to a different ceiling,
and never lowers a scale. A server that renames its tools can cause more of its
own calls to be charged and can never cause fewer.

## Compile time only

Every binding produced here is written into a draft a person reviews, exactly as
`policy_draft` and `compile_ontology` do. Nothing in this module runs on a
decision path, and the runtime that consumes its output is the same deterministic
budget check it always was.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from clayseal.capabilities.freshness import _akin
from clayseal.capabilities.mandate_lint import EFFECT_FAMILIES
from clayseal.capabilities.obligations import _tokens
from clayseal.capabilities.tool_verbs import classify_verb

__all__ = ["Binding", "Ceiling", "derive_tracked", "merge_tracked", "refute"]

#: Verbs whose calls can spend. A read never debits, whatever its arguments look
#: like: `get_quote(amount=...)` prices a thing and moves nothing, and charging
#: it against a payment ceiling refuses honest work in the middle of a task,
#: which is the expensive direction of this error.
_SPENDING = frozenset({"write", "send", "transfer"})

#: Argument-name fragments that carry the size of an effect. Same list as
#: `policy_scaffold._AMOUNT` in spirit; kept separate so a change there for
#: rendering reasons cannot silently change what gets charged.
#:
#: Preferred but not sufficient, for the reason `policy_draft` records about its
#: own marker list: a phrase list loses on phrasing it has not seen. It missed
#: `fee`, `delta` and `tons`, and two of those are ordinary names for an amount
#: of money. The structural signal below is what ends that arms race.
_QUANTITY = ("amount", "value", "total", "sum", "price", "cost", "qty",
             "quantity", "notional", "size", "units", "count", "limit")

#: Numeric arguments that are an IDENTIFIER or a paging control rather than the
#: size of an effect. Without these the structural rule reads `page` and
#: `order_id` as quantities and charges a ceiling for turning a page.
#:
#: Durations are here for a reason worth keeping. `advance_clock(hours=24)` is a
#: number, is not a read, and against a money ceiling debited 24 dollars for
#: moving the clock a day. A duration is how LONG, never how much, and a value
#: budget has no use for it.
_NOT_A_QUANTITY = ("id", "index", "idx", "page", "offset", "version", "seq",
                   "timestamp", "time", "date", "year", "month", "day", "ttl",
                   "port", "retries", "attempt", "priority", "rank",
                   "hour", "minute", "second", "week", "duration", "days",
                   "delay", "interval", "timeout", "age")


@dataclass(frozen=True)
class Ceiling:
    """One limit from the document, and the sentence it was read out of."""

    budget_id: str
    #: The verbatim sentence. Carried so a derived binding can cite WHY, and
    #: used as evidence by the lexical tier when there is more than one ceiling.
    source: str = ""


@dataclass(frozen=True)
class Binding:
    """One derived debit: `tool` charges `amount_arg` against `budget_id`."""

    tool: str
    amount_arg: str
    budget_id: str
    #: sole | lexical | proposed. Rendered as `source:` in the draft so a
    #: reviewer can see which of these was a real inference and which was not.
    tier: str
    why: str
    #: Arguments naming the OBJECT the effect lands on. When set, the ledger
    #: makes the effect once-per-object, which is what stops one invoice being
    #: paid twice through two calls that are each individually within the
    #: ceiling. Empty unless `identity` was asked for; see `_identity_args`.
    identity_args: tuple[str, ...] = ()
    #: Would the conservative reading have produced this binding too? False marks
    #: a debit that exists only because the permissive default charges anything
    #: that is not a read, which makes it the first thing refutation drops.
    strict_ok: bool = True

    def as_yaml(self, indent: str = "      ") -> list[str]:
        return [f"{indent}# why: {self.why}",
                f"{indent}{self.tool}: {{arg: {self.amount_arg}, "
                f"budget: {self.budget_id}, source: inferred, tier: {self.tier}}}"]


def _quantity_arg(args: Iterable[tuple[str, str]]) -> str | None:
    """The argument carrying the size of the effect, or None.

    Two passes, named first and structural second. `args` is (name, JSON type).

    The structural pass is the one that matters. An argument the server declared
    as a number, whose name is not an identifier or a paging control, is a
    quantity whatever it is called, and that is what reaches `fee`, `delta` and
    `tons`. It is the same move `policy_draft` made when it stopped matching
    phrases for money and started matching money: the signal is in the shape,
    and the shape does not have a vocabulary to fall behind.

    Named first, because when a tool has two numeric arguments the one called
    `amount` is the one being spent.
    """
    args = [(str(n), str(t or "")) for n, t in args]
    for name, _type in args:
        if any(frag in name.lower() for frag in _QUANTITY):
            return name
    for name, type_ in args:
        low = name.lower()
        if type_ in ("number", "integer") and not any(
                frag in low for frag in _NOT_A_QUANTITY):
            return name
    return None


def _identity_args(args: Iterable[tuple[str, str]], amount_arg: str,
                   mode: str) -> tuple[str, ...]:
    """Arguments naming the object an effect lands on.

    `named` uses `policy_scaffold._IDENTITY`, which recognises id-shaped names.
    `all` takes every non-quantity argument, which is the structural reading:
    what a call is ABOUT is whatever is left once you remove how much.

    The two differ, and the difference is not free. `all` closes the double-pay
    class, where one invoice is paid twice through two calls that are each within
    the ceiling and `_IDENTITY` sees no id-shaped name in `pay_bonus(amount,
    employee, period)`. It also makes every effect once-per-object, so a grant
    that legitimately pays the same vendor twice is refused the second time.
    Which of those costs more is a measurement, not a judgement.
    """
    if mode == "off":
        return ()
    pairs = [(str(n), str(t or "")) for n, t in args if str(n) != amount_arg]
    if mode == "named":
        from clayseal.capabilities.policy_scaffold import _IDENTITY
        return tuple(n for n, _ in pairs if _IDENTITY.search(n.lower()))
    return tuple(n for n, t in pairs if t in ("", "string", "integer", "number"))


def _spends(name: str, description: str = "", *, strict: bool = False) -> bool:
    """Does this tool move a quantity, as opposed to reporting one?

    The verb decides, and an effect family overrides it. `classify_verb` reads a
    tool's prefix, so a name whose prefix is not in its lists comes back `call`;
    `authorize_payout` and `settle_invoice` are both effects and neither leads
    with a known verb. Membership in a value family is enough on its own, which
    is the same list `mandate_lint` already uses to find key-splitting.

    **The unclassified case is the whole question, and `strict` is which way it
    defaults.** Strict demands positive evidence of spending; permissive charges
    anything that is not a read. The two differ on exactly the tools an attacker
    would choose: `cashout_chips`, `file_claim`, `force_replay` and
    `record_ops_adjustment` all carry a quantity, all move money, and none of
    them says so in a word a list could hold. `record_ops_adjustment` is
    described as "looks like bookkeeping", which is the point.

    Neither default is obviously right, because they trade the two halves of the
    joint metric against each other: a missed debit means the ceiling does not
    bind and the attack lands, and a spurious one refuses honest work. Both are
    reachable here so the choice can be measured instead of argued.
    """
    low = name.lower()
    if any(frag in low for frag in EFFECT_FAMILIES["value"]):
        return True
    verb = classify_verb(name)
    if verb == "read":
        return False
    if verb in _SPENDING:
        return True
    # The server's own prose may raise a tool to an effect and never lower it,
    # the same asymmetry `policy_scaffold` applies to the verb itself: prose that
    # talks an effect down is the shape of a server describing itself favourably.
    prose = (description or "").lower()
    if any(word in prose for word in
           ("pays", "pay ", "transfers", "sends money", "debits", "charges",
            "disburses", "withdraws", "settles", "remits")):
        return True
    return not strict


def _evidence(ceiling: Ceiling) -> set[str]:
    """Words a ceiling gives the lexical tier to match on."""
    return _tokens(ceiling.budget_id.replace("_", " ")) | _tokens(ceiling.source)


def _lexical_pick(name: str, description: str,
                  ceilings: list[Ceiling]) -> Ceiling | None:
    """The ceiling whose words most overlap this tool's, or None if it is a tie.

    A tie is not resolved. Two ceilings that a tool matches equally well is
    exactly the case `tracked_block` warns about, where naming the wrong one
    splits a shared limit in two and still reads as working policy. Returning
    nothing sends it to the next tier or to the operator.
    """
    words = _tokens(name.replace("_", " ")) | _tokens(description)
    scored = []
    for ceiling in ceilings:
        want = _evidence(ceiling)
        hits = sum(1 for w in words for e in want if _akin(w, e))
        scored.append((hits, ceiling))
    scored.sort(key=lambda pair: pair[0], reverse=True)
    if not scored or scored[0][0] == 0:
        return None
    if len(scored) > 1 and scored[1][0] == scored[0][0]:
        return None
    return scored[0][1]


def derive_tracked(
    ceilings: Iterable[Ceiling | str],
    tools: Iterable[Mapping[str, object]] | object,
    *,
    strict: bool = False,
    identity: str = "off",
    propose: object = None,
) -> list[Binding]:
    """Derive `budgets.tracked` from the ceilings and the tool catalogue.

    `tools` is either a `policy_scaffold.Catalog` or an iterable of mappings
    carrying `name`, `description` and an argument list under `args`,
    `parameters` or `properties`. `propose`, if given, is called once with the
    unbound remainder and returns `{tool: budget_id}`; it is the only place a
    model can enter and it is never imported by this module.

    Sees the ceilings and the catalogue. Never a goal, never a trajectory, never
    a tool result.
    """
    limits = [c if isinstance(c, Ceiling) else Ceiling(str(c)) for c in ceilings]
    if not limits:
        return []
    facts = _read_tools(tools)

    out: list[Binding] = []
    unbound: list[tuple[str, str, str, tuple[str, ...]]] = []
    for name, description, args in facts:
        arg = _quantity_arg(args)
        if arg is None or not _spends(name, description, strict=strict):
            continue
        ident = _identity_args(args, arg, identity)
        firm = _spends(name, description, strict=True)
        if len(limits) == 1:
            out.append(Binding(
                name, arg, limits[0].budget_id, "sole",
                f"the grant states one ceiling, {limits[0].budget_id}, and "
                f"{name} carries {arg}", ident, firm))
            continue
        pick = _lexical_pick(name, description, limits)
        if pick is not None:
            out.append(Binding(
                name, arg, pick.budget_id, "lexical",
                f"{name} shares wording with {pick.source or pick.budget_id!r}",
                ident, firm))
        else:
            unbound.append((name, description, arg, ident))

    if unbound and callable(propose):
        proposed = propose([
            {"name": n, "description": d, "amount_arg": a} for n, d, a, _ in unbound
        ], [{"budget_id": c.budget_id, "source": c.source} for c in limits]) or {}
        known = {c.budget_id for c in limits}
        for name, _desc, arg, ident in unbound:
            target = proposed.get(name)
            # A proposal naming a ceiling that does not exist is discarded rather
            # than created. Inventing a budget id makes an unbounded one, which
            # reads in the draft as a limit and enforces nothing.
            if isinstance(target, str) and target in known:
                out.append(Binding(name, arg, target, "proposed",
                                   f"proposed for {name} from the tool schema",
                                   ident, False))
    return out


def _read_tools(tools: object) -> list[tuple[str, str, list[tuple[str, str]]]]:
    """Normalise the two catalogue shapes this repo already has.

    Returns (name, description, [(arg, JSON type)]). A `Catalog` has already
    thrown the types away, so its `amount_args` are reported as numbers: they
    passed `policy_scaffold`'s own amount test to get into that field.
    """
    catalog_tools = getattr(tools, "tools", None)
    if catalog_tools is not None:
        return [(t.name, getattr(t, "description", ""),
                 [(a, "number") for a in getattr(t, "amount_args", ())])
                for t in catalog_tools]
    out: list[tuple[str, str, list[tuple[str, str]]]] = []
    if not isinstance(tools, Iterable):
        return out
    for entry in tools:
        if not isinstance(entry, Mapping):
            continue
        fn = entry.get("function", entry)
        if not isinstance(fn, Mapping):
            continue
        name = str(fn.get("name") or "")
        if not name:
            continue
        params = fn.get("parameters") or fn.get("inputSchema") or {}
        props = params.get("properties") if isinstance(params, Mapping) else None
        args: list[tuple[str, str]] = []
        if isinstance(props, Mapping):
            for key in sorted(props):
                spec = props[key]
                type_ = spec.get("type") if isinstance(spec, Mapping) else None
                args.append((str(key), str(type_ or "")))
        out.append((name, str(fn.get("description") or ""), args))
    return out


def refute(bindings: list[Binding], ceilings: Mapping[str, float],
           good_traces: Iterable[Iterable[tuple[str, Mapping[str, object]]]],
           *, windowed: Iterable[str] = ()) -> tuple[list[Binding], list[str]]:
    """Drop every binding that legitimate traffic contradicts.

    `validate_ontology` established this rule for compiled preconditions, where
    it took an artifact from a wash to +10 at p=0.002: **a declaration that
    known-good traffic violates is not a declaration, it is a mistake.** The
    same rule applies here and refutes two different errors.

    *A ceiling the honest work exceeds.* If replaying a legitimate trace against
    the derived map breaches a ceiling, some tool in that budget does not really
    debit it. `refund_in` says so in its own description, "does not replenish
    gross outflow budget"; the permissive default charged it anyway. Bindings are
    dropped weakest-evidence first, one at a time, until the trace fits.

    *An identity the honest work repeats.* If a legitimate trace calls the same
    tool twice with the same identity, the effect is not once-per-object and the
    identity is dropped rather than the debit. That keeps the ceiling and gives
    up only the dedup.

    Returns the surviving bindings and a line per drop, for the draft.

    `windowed` names budgets whose ceiling is per-window rather than per-session.
    A trace's running total is not evidence against those: `rolling-window-hour-skew`
    legitimately pays 2,000 twice against a 3,000 rolling ceiling with a day
    between them, and a session-total reading calls that a breach and drops the
    one binding that was right. Where the window is not known, saying nothing is
    the safe answer, so those budgets are skipped.

    **A limit worth stating plainly.** Traffic here only ever REMOVES a binding.
    It never proposes one, because a grant inferred from observed behaviour false
    blocks 42.99% of held-out work: what an agent has done is not evidence of
    what it is allowed to do. Refutation is sound in the direction that widens.
    """
    live = list(bindings)
    notes: list[str] = []
    skip = frozenset(windowed or ())

    def contribution(b: Binding, trace) -> float:
        total = 0.0
        for tool, args in trace:
            if tool != b.tool:
                continue
            try:
                total += float((args or {}).get(b.amount_arg) or 0.0)
            except (TypeError, ValueError):
                continue
        return total

    # Weakest first: a proposal, then a permissive-only debit, then a lexical
    # match, then a firm one. Ties break on the SMALLEST contribution to the
    # trace, which is minimal repair: the breach is explained by removing as
    # little enforcement as accounts for it. Breaking on the tool's name instead
    # dropped `pay_external`, the binding that was right, and kept `transfer`,
    # the one that was not, purely because `p` sorts before `t`.
    def weakness(b: Binding, trace) -> tuple[int, float, str]:
        return ({"proposed": 0, "lexical": 2, "sole": 3}[b.tier]
                - (0 if b.strict_ok else 2), contribution(b, trace), b.tool)

    traces = [list(t) for t in good_traces or ()]

    for trace in traces:
        seen: dict[tuple[str, tuple], int] = {}
        for tool, args in trace:
            b = next((x for x in live if x.tool == tool), None)
            if b is None or not b.identity_args:
                continue
            key = (tool, tuple(str((args or {}).get(a, "")) for a in b.identity_args))
            seen[key] = seen.get(key, 0) + 1
            if seen[key] > 1:
                live = [x if x.tool != tool else
                        Binding(x.tool, x.amount_arg, x.budget_id, x.tier,
                                x.why, (), x.strict_ok) for x in live]
                notes.append(f"{tool}: identity dropped, legitimate work repeats "
                             f"the same object")

    def breached(trace) -> str | None:
        spent: dict[str, float] = {}
        for tool, args in trace:
            b = next((x for x in live if x.tool == tool), None)
            if b is None:
                continue
            try:
                amount = float((args or {}).get(b.amount_arg) or 0.0)
            except (TypeError, ValueError):
                continue
            spent[b.budget_id] = spent.get(b.budget_id, 0.0) + amount
        for budget, total in spent.items():
            limit = ceilings.get(budget)
            if budget in skip or limit is None:
                continue
            if total > float(limit) + 1e-6:
                return budget
        return None

    for trace in traces:
        # Bounded by the number of bindings, so a trace that can never fit stops
        # rather than looping: a ceiling the honest work exceeds with NOTHING
        # bound is a fact about the grant and not about this derivation.
        for _ in range(len(live) + 1):
            budget = breached(trace)
            if budget is None:
                break
            guilty = sorted((x for x in live if x.budget_id == budget),
                            key=lambda b: weakness(b, trace))
            if not guilty:
                break
            drop = guilty[0]
            live = [x for x in live if x is not drop]
            notes.append(f"{drop.tool}: dropped, legitimate work drives "
                         f"{budget} past its ceiling with it bound")
    return live, notes


def merge_tracked(declared: Mapping[str, object],
                  derived: Iterable[Binding]) -> dict[str, object]:
    """Add derived bindings to what an operator wrote. Never overwrite one.

    The monotone rule, in one function. A tool the operator already bound keeps
    the operator's binding whatever the catalogue now says about it, because the
    catalogue is written by the party being constrained and this is the field it
    would most want to move.
    """
    out = dict(declared or {})
    for binding in derived:
        if binding.tool in out:
            continue
        out[binding.tool] = (binding.amount_arg, binding.budget_id)
    return out
