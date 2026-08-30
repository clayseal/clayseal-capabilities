"""Precedence: an action that requires a prior one, read from the sealed goal.

A budget is a ceiling on a running total, and it is the constraint this gateway
enforces well: 83.3% containment where the grant states a countable limit
against 18.9% where it does not. The scenarios in that second group are not
harder in some diffuse way. Many state a different SHAPE of rule, an ordering:

    "Full checklist before irreversible commit"
    "No ship without cook-temp CCP"
    "IRE clearance before EC weight release"

A counter cannot express that, for the same reason a stateless gate cannot
express a total. The accumulator has to hold *which actions have happened*, not
just how many.

**Trust basis, which is the same one `derive_counts` already uses.** The rule is
read from the SEALED GOAL, fixed before any untrusted content exists, never from
tool output and never from an argument. `LLMQueryPlanner` guarantees the goal was
compiled from the user's request and the tool catalogue alone.

**Off by default.** Deriving a rule from a sentence is inference, and inference
that refuses legitimate work is worse than no rule. The cost is measured rather
than assumed; see `benchmarks/results/obligations.md`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: "<prerequisite> before <gated>" and "no <gated> without <prerequisite>".
#: Deliberately two narrow forms rather than a grammar: a parser that matches
#: loosely on a policy sentence invents obligations, and an invented obligation
#: refuses work nobody prohibited.
_BEFORE = re.compile(r"^(?P<pre>.{3,60}?)\s+before\s+(?P<gated>.{3,60})$", re.IGNORECASE)
_WITHOUT = re.compile(r"^no\s+(?P<gated>.{3,60}?)\s+without\s+(?P<pre>.{3,60})$", re.IGNORECASE)

_STOP = frozenset({
    "the", "a", "an", "any", "all", "full", "and", "or", "of", "to", "for",
    "on", "in", "with", "per", "its", "each", "every", "complete", "completed",
})


def _tokens(phrase: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", phrase.lower())
            if len(t) > 2 and t not in _STOP}


def _match_tools(phrase: str, catalog: set[str]) -> frozenset[str]:
    """Tools whose name shares a significant token with `phrase`.

    Token overlap rather than an embedding: the catalogue is small, enumerable
    and trusted, and a nearest-neighbour match that is 80% right is a rule that
    blocks the wrong tool 20% of the time.
    """
    want = _tokens(phrase)
    if not want:
        return frozenset()
    hits = set()
    for tool in catalog:
        if _tokens(tool) & want:
            hits.add(tool)
    return frozenset(hits)


@dataclass(frozen=True)
class Obligation:
    """`gated` may not run until every tool in `requires` has run."""

    gated: frozenset[str]
    requires: frozenset[str]
    source: str

    def describe(self) -> str:
        return (f"{sorted(self.gated)} requires {sorted(self.requires)} "
                f"(from sealed goal: {self.source!r})")


def derive_obligations(goal_summary: str, catalog: set[str]) -> list[Obligation]:
    """Obligations stated by the sealed goal, or an empty list.

    Returns nothing rather than guessing when either side of the rule fails to
    resolve to a tool. A rule that names a prerequisite the session cannot
    perform would deny the gated action forever.
    """
    out: list[Obligation] = []
    for clause in re.split(r"[;.]|,\s*(?=no\b)", goal_summary or ""):
        clause = clause.strip()
        if not clause:
            continue
        for pattern in (_WITHOUT, _BEFORE):
            m = pattern.match(clause)
            if not m:
                continue
            gated = _match_tools(m.group("gated"), catalog)
            requires = _match_tools(m.group("pre"), catalog)
            # Both sides must resolve, and a tool cannot be its own prerequisite.
            gated, requires = gated - requires, requires - gated
            if gated and requires:
                out.append(Obligation(gated, requires, clause))
            break
    return out


@dataclass
class ObligationLedger:
    """Which prerequisites this session has satisfied."""

    obligations: list[Obligation] = field(default_factory=list)
    _seen: set[str] = field(default_factory=set)

    def observe(self, tool: str) -> None:
        self._seen.add(tool)

    def check(self, tool: str) -> tuple[bool, str]:
        """(allowed, reason). Allowed when no obligation gates this tool."""
        for ob in self.obligations:
            if tool in ob.gated:
                missing = ob.requires - self._seen
                if missing:
                    return False, (
                        f"{tool!r} requires {sorted(missing)} first, from the "
                        f"sealed goal: {ob.source!r}")
        return True, ""
