"""Derive the session rungs from the sealed goal and the tool catalogue.

WHY THIS MODULE EXISTS
----------------------
The four goal-derived rungs shipped as library primitives with `derive_*`
functions, docstrings, and tests, and **nothing in this package ever called
them**. `SessionBroker` declared `obligations`, `freshness`, `identity` and
`entities` as `Any | None = None`, each with a comment telling a caller to build
one, and `DeployableStack.from_goal` had no parameter to pass one through. The
only caller was the benchmark harness, which built a broker and set the
attributes by hand.

So the measured configuration and the shipped configuration were different
systems. A deployment following the documented path got the base gateway; the
published joint containment came from an arm no supported factory could
construct. That is not a documentation gap, it is the benchmark measuring
something the product does not do.

This module closes it. `from_goal` calls `derive_session_rungs` on the same two
trusted inputs the benchmark used, so the deployment path and the measured path
build the same broker.

WHAT MAY BE READ
----------------
Two inputs, both fixed before any untrusted content exists:

  the sealed goal      its `structured_intent` (authority, may deny) and its
                       `summary` prose (a reading, escalates)
  the tool catalogue   the names the mandate granted

Never the trajectory, a tool result, or anything an attacker can influence.
That is the provenance rule, and derivation is safe precisely because it runs
before the session opens. Each rung derives nothing when its clause does not
resolve against the catalogue, which fails closed.
"""
from __future__ import annotations

import re
from typing import Any

__all__ = ["derive_session_rungs", "rungs_from_compiled", "DerivedRungs"]


class DerivedRungs(dict):
    """The rungs derived for a session, and which ones fired.

    A plain dict of broker kwargs, plus `derived` naming the rungs that produced
    a rule. A deployment that wants to know whether its goal text actually said
    anything enforceable reads that set, rather than guessing from behaviour.
    """

    @property
    def derived(self) -> frozenset[str]:
        return frozenset(k for k, v in self.items() if v is not None)


def derive_session_rungs(
    goal: Any,
    catalog: set[str] | frozenset[str] | None = None,
) -> DerivedRungs:
    """Read the four goal-derived rungs out of `goal` and `catalog`.

    Returns broker kwargs. A rung whose clause does not resolve is absent rather
    than permissive: no rule means the rung never fires, and the floor still
    applies.
    """
    summary = str(getattr(goal, "summary", "") or "")
    intent = getattr(goal, "structured_intent", None)
    tools = set(catalog or ())

    out = DerivedRungs(
        obligations=_obligations(summary, tools),
        entities=_entities(summary, intent),
        freshness=_freshness(summary, tools),
        identity=_identity(summary),
    )
    return out


def _obligations(summary: str, catalog: set[str]) -> Any | None:
    """Precedence: "A before B", "no B without A"."""
    if not summary or not catalog:
        return None
    from clayseal.capabilities.obligations import ObligationLedger, derive_obligations

    rules = derive_obligations(summary, catalog)
    return ObligationLedger(obligations=rules) if rules else None


def _entities(summary: str, intent: Any) -> Any | None:
    """Entity binding, structured intent first.

    The order carries the provenance split. A list the operator sealed in
    structured form is authority and may deny; the same constraint read out of
    prose is an interpretation and escalates. `bindings_from_intent` is tried
    first for that reason, not because it is more convenient.
    """
    from clayseal.capabilities.entities import (
        EntityLedger,
        bindings_from_intent,
        derive_bindings,
    )

    bindings = bindings_from_intent(intent)
    if not bindings and summary:
        bindings = derive_bindings(summary)
    return EntityLedger(bindings=bindings) if bindings else None


def _freshness(summary: str, catalog: set[str]) -> Any | None:
    """Freshness: "A voids on B", "B under live A".

    The goal must NAME the invalidator. Where it does not this derives nothing
    rather than guessing which call moves the world, because guessing wrong
    refuses ordinary work.
    """
    if not summary or not catalog:
        return None
    from clayseal.capabilities.freshness import FreshnessLedger, derive_invalidations

    lead = re.match(r"^(\w+)", summary)
    rules = derive_invalidations(
        summary, catalog, goal_verb=lead.group(1) if lead else None
    )
    return FreshnessLedger(invalidations=rules) if rules else None


def _identity(summary: str) -> Any | None:
    """Independence, armed only by a goal that asks for distinctness.

    The root map is built from mints this session watched go past, so the rung
    decides on a fact about history rather than a claim about who anyone is.
    """
    if not summary:
        return None
    from clayseal.capabilities.identity import derive_identity_rules

    return derive_identity_rules(summary)


def rungs_from_compiled(compiled: dict | None, clause: str) -> DerivedRungs:
    """Build the same four ledgers from a COMPILED mapping instead of a regex.

    `derive_session_rungs` reads the operator's sentence with hand-written
    clause patterns: two forms for precedence, three for freshness, one for
    entities, a substring test for independence. They are correct and they are
    the ceiling, because an operator who writes "A must precede B" or writes in
    German derives nothing.

    This takes the same rules from a compile step over the clause and the tool
    schemas (`benchmarks/compile_roles.compile_rules`) and hands them to the
    SAME deterministic ledgers. The enforcement path is unchanged; only where
    the rule came from is different, and both sources are fixed before any
    untrusted content exists.

    A compiled mapping that names no rule yields no ledger, exactly as an
    unmatched clause pattern does.
    """
    from clayseal.capabilities.entities import EntityBinding, EntityLedger
    from clayseal.capabilities.freshness import FreshnessLedger, Invalidation
    from clayseal.capabilities.identity import IdentityLedger
    from clayseal.capabilities.obligations import Obligation, ObligationLedger

    src = (clause or "").strip()
    if not compiled:
        return DerivedRungs(obligations=None, entities=None,
                            freshness=None, identity=None)

    obligations = [
        Obligation(gated=str(p["after"]), requires=frozenset({str(p["before"])}),
                   source=src)
        for p in compiled.get("precedence") or []
    ]
    # `establishes` and `subject` are BOTH frozensets, and `subject` is the
    # token set `Invalidation.consumes` matches an action against. Passing a
    # bare string for the first and None for the second type-checked fine and
    # crashed the gateway at decision time on `set(self.subject)`, on five
    # scenarios, scored as neither contained nor escaped. The sweep's own
    # `test_no_gate_raises_on_any_scripted_action` is what caught it, which is
    # the whole reason that test exists: a gate that raises has not contained
    # anything, it has crashed.
    from clayseal.capabilities.freshness import _stems

    invalidations = []
    for v in compiled.get("invalidations") or []:
        establishes = frozenset({str(v["establishes"])})
        invalidators = frozenset(str(t) for t in v["invalidators"])
        if not establishes - invalidators:
            continue
        invalidations.append(Invalidation(
            establishes=establishes - invalidators,
            invalidators=invalidators,
            # The tokens of the establishing tool's own name. The lexical path
            # stems the clause phrase; the compiled path has already resolved
            # that phrase to a tool, so its name is the more precise subject.
            subject=frozenset(_stems(str(v["establishes"]).replace("_", " "))),
            source=src))
    bindings = [
        # `declared=False`: a rule read out of prose by a model is an
        # interpretation of that prose, not the operator's structured
        # authority, so it escalates rather than denying. Same provenance split
        # the lexical rung already draws between `structured_intent` and a
        # summary sentence, and it applies here for the same reason.
        EntityBinding(str(e["key"]),
                      frozenset(str(v).lower().replace(" ", "")
                                for v in e["allowed"]),
                      False, "compiled")
        for e in compiled.get("entities") or []
    ]
    distinct = bool(compiled.get("distinct_subjects"))
    idem = bool(compiled.get("idempotency"))

    return DerivedRungs(
        obligations=ObligationLedger(obligations=obligations) if obligations else None,
        entities=EntityLedger(bindings=bindings) if bindings else None,
        freshness=FreshnessLedger(invalidations=invalidations) if invalidations else None,
        identity=(IdentityLedger(distinct_subjects=distinct, idempotency=idem,
                                 separation=False, source=src)
                  if (distinct or idem) else None),
    )


def refuted_by_traffic(compiled: dict | None, trace: list[tuple[str, Any]],
                       clause: str) -> dict | None:
    """Drop every compiled rule that known-good traffic contradicts.

    A rule legitimate traffic breaks is not a rule. This is the same discipline
    `preconditions.refuted_by` applies to a compiled ontology, where it takes the
    artifact from +9 -8 at p=1.0, a wash, to +10 -0 at p=0.002, and it applies
    here for a sharper reason: the measured failure mode of asking a model to
    author rules is not missing catches, it is INVENTING constraints the operator
    never stated, which refuses their own work. On this suite that cost 17 benign
    twins against 2 (`compiled_vs_lexical_rungs.md`). Replaying benign traffic is
    what removes exactly those and keeps the rest.

    Each candidate is tested ALONE, in a ledger holding only itself, against the
    real `check`/`observe` path. Testing them together would let one rule's
    refusal mask another's, and would drop a good rule because a bad one fired
    first.

    `trace` is a sequence of (tool, args) a correct agent produced. It needs no
    labels, no attacks and no human review, which is what makes this deployable:
    an operator validates against their own logs.
    """
    if not compiled:
        return compiled

    def survives(rung_key: str, rule: Any) -> bool:
        one = rungs_from_compiled({**_EMPTY, rung_key: [rule]}, clause)
        led = one.get(_LEDGER_OF[rung_key])
        if led is None:
            return False
        for tool, args in trace:
            verb = _verb(tool)
            r = _CHECK[rung_key](led, tool, verb, args)
            if not (bool(r[0]) if isinstance(r, tuple) else bool(r)):
                return False
            _OBSERVE[rung_key](led, tool, verb, args)
        return True

    out = dict(compiled)
    out["precedence"] = [r for r in compiled.get("precedence") or []
                         if survives("precedence", r)]
    out["invalidations"] = [r for r in compiled.get("invalidations") or []
                            if survives("invalidations", r)]
    out["entities"] = [r for r in compiled.get("entities") or []
                       if survives("entities", r)]
    return out


_EMPTY = {"precedence": [], "invalidations": [], "entities": [],
          "distinct_subjects": False, "idempotency": False}
_LEDGER_OF = {"precedence": "obligations", "invalidations": "freshness",
              "entities": "entities"}


#: Each ledger's real signature, dispatched by rung rather than probed.
#:
#: Probing was wrong and wrong in the dangerous direction. `EntityLedger.check`
#: takes (tool, args) and the probe tried `check(tool)` first; that raised no
#: TypeError for `ObligationLedger` and for `EntityLedger` the probe never
#: reached the args form, so every entity rule was evaluated against no
#: arguments, nothing was ever out of range, and NO entity rule was ever
#: refuted. The arm then refused benign work with rules the refutation was
#: supposed to have dropped: `vendor: ['vendors']`, the literal word from the
#: clause, refusing every real vendor name.
_CHECK = {
    "precedence":    lambda led, tool, verb, args: led.check(tool),
    "invalidations": lambda led, tool, verb, args: led.check(tool, verb),
    "entities":      lambda led, tool, verb, args: led.check(tool, args),
}
_OBSERVE = {
    "precedence":    lambda led, tool, verb, args: led.observe(tool),
    "invalidations": lambda led, tool, verb, args: led.observe(tool, verb),
    "entities":      lambda led, tool, verb, args: None,   # holds no history
}


def _verb(tool: str) -> str:
    """The verb the gateway will actually classify this tool as.

    Passing an empty string here silently broke the refutation: `Invalidation`
    only fires when the verb is in `_CONSUMING`, so with no verb no freshness
    rule ever appeared to refuse benign traffic and none was ever dropped.
    """
    from clayseal.capabilities.tool_verbs import classify_verb

    return classify_verb(tool)
