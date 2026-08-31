"""Invalidation: the justification went stale before the action consumed it.

`obligations.py` reads precedence out of the sealed goal, "A before B". This
reads its mirror image, and the mirror image is the harder half:

    Clean-approval voids on later dirt
    Approvals bind to pre-amendment fields
    Pay on live bit; checks destroy it

A precedence rule says an action may not run *until* something has happened. An
invalidation rule says an action may not run *after* something has happened,
because the thing that authorised it no longer holds. Every field of the action
is correct; what is wrong is that its justification is stale, and the
justification is not part of the action, so no function of the action alone can
see it. In these scenarios the stale call and the legitimate call are identical
on the wire, which is why scope, binding, budgets, velocity and flow control all
return the same answer for both.

## Version, never a timer

Staleness is a comparison and not a judgement. A five-second-old view of a hot
ledger is stale and a five-day-old view of an archived record is not, so age is a
proxy for change while change is directly observable. The version used here is
the strongest one a gateway gets for free: **an effect this session performed on
the object, which moves it by definition.** The session watched the invalidator
go past.

## Poisoned, then cleared

An invalidator poisons the justification. Re-establishing it clears the poison,
which is what makes this a freshness rule rather than a one-way ban: the agent
that re-approves after amending is doing the right thing and must not be
refused. `policy-version-skew`'s benign twin does exactly that, re-planning after
the policy upgrade, and it has to keep completing.

## What it refuses to derive

Only a goal that NAMES the invalidator arms this. `"Pay INV-5 only while
approved"` does not: what moves the approval is `tick_world`, a clock advance
sharing no token with any part of the goal, and a rule that guessed at it would
be guessing. Absent a named invalidator this returns nothing, so a mandate
written before this module behaves exactly as it did.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from clayseal.capabilities.obligations import _tokens

#: Verbs that consume a justification rather than merely observing it. A read of
#: a stale approval is not the harm; paying against one is.
_CONSUMING = frozenset({"transfer", "pay", "write", "execute", "send", "post",
                        "create", "delete", "update"})

#: Verbs that MOVE a thing, as opposed to reading it. Used only by the
#: "under live X" form, where the goal names what must be current without naming
#: what changes it, so the invalidator has to be recognised from the catalogue.
_MUTATING = frozenset({"upgrade", "update", "change", "set", "revise", "amend",
                       "modify", "rotate", "bump", "migrate", "replace",
                       "publish", "promote"})

#: "<justification> voids on [later] <invalidator>", and its siblings. Each names
#: the invalidator explicitly, which is the whole precondition for arming.
_CLAUSES = (
    re.compile(r"(?P<just>.+?)\s+(?:voids?|expires?|lapses?)\s+on\s+"
               r"(?:later\s+|any\s+)?(?P<inv>.+)", re.IGNORECASE),
    re.compile(r"(?P<just>.+?)\s+binds?\s+to\s+pre[-\s](?P<inv>\w+)",
               re.IGNORECASE),
    re.compile(r"(?P<just>.+?)[;,]\s*(?P<inv>\w+)s?\s+"
               r"(?:destroys?|breaks?|voids?|invalidates?)\s+it",
               re.IGNORECASE),
)

#: "<consumer> under live <thing>". The goal names WHAT must be current and not
#: what moves it, so the invalidator is recognised from the catalogue instead of
#: from the sentence: a tool that both names the thing and carries a mutating
#: verb. Deliberately does not accept "fresh", because "at fresh FX" needs
#: re-reading immediately before use and not "do not act after X", and treating
#: the two alike would refuse the benign twin that refreshes.
# Anchored and non-backtracking. `.+?` before a `.+` tail is super-linear on a
# long non-matching string, which the library's regex audit catches: a goal
# summary is attacker-adjacent input in a gateway that compiles one per session,
# so a pattern that degrades on 8 KB of text is a denial-of-service surface and
# not merely slow. Both halves are now bounded character classes.
_LIVE = re.compile(
    r"(?P<just>[^,;]{1,120}?)\s+(?:under|against|at|on)\s+(?:the\s+)?"
    r"(?:live|current|latest|in-force)\s+(?P<subj>[^,;]{1,120})\Z",
    re.IGNORECASE)


def _akin(a: str, b: str) -> bool:
    """Are these the same word to a reader?

    A goal writes "Approvals" where a tool is called `approve_draft`, and "dirt"
    where the tool is `mark_dirty_event`. Suffix stripping does not bridge
    either, so this compares shared prefixes: at least four characters and at
    least 70% of the shorter word. That is deliberately weaker than a stemmer
    and the weakness is bounded, because a rule arms only when BOTH of its sides
    resolve to a tool AND the goal states an invalidation clause. A short token
    like "pay" has to match exactly.
    """
    if a == b:
        return True
    n = 0
    for x, y in zip(a, b, strict=False):
        if x != y:
            break
        n += 1
    return n >= 4 and n >= 0.7 * min(len(a), len(b))


def _stems(phrase: str) -> set[str]:
    return _tokens(phrase)


def _akin_any(tool: str, want: set[str]) -> bool:
    return any(_akin(t, w) for t in _tokens(tool) for w in want)


def _matching(phrase: str, catalog) -> frozenset[str]:
    """Tools whose name shares a word with `phrase`."""
    want = _tokens(phrase)
    return frozenset(t for t in catalog if _akin_any(t, want))


@dataclass(frozen=True)
class Invalidation:
    """One rule: `invalidators` poison `establishes`, and `subject` names it."""

    establishes: frozenset[str]
    invalidators: frozenset[str]
    subject: frozenset[str]
    source: str

    def consumes(self, tool: str, verb: str) -> bool:
        """Does this action SPEND the justification this rule protects?"""
        return (str(verb).lower() in _CONSUMING
                and _akin_any(tool, set(self.subject)))


def derive_invalidations(goal_summary: str, catalog, *,
                         goal_verb: str | None = None) -> list[Invalidation]:
    """Read invalidation clauses from the sealed goal. Nothing else is a source.

    `goal_verb` widens the protected subject to the goal's own leading verb, for
    a goal that names the invalidator but refers to the justification only as
    "it". Returns nothing rather than guessing when either side fails to resolve
    to a tool.
    """
    catalog = frozenset(catalog or ())
    out: list[Invalidation] = []
    for clause in re.split(r"(?<![;,])\.\s", goal_summary or ""):
        for pattern in _CLAUSES:
            m = pattern.search(clause.strip())
            if not m:
                continue
            just, inv = m.group("just"), m.group("inv")
            invalidators = _matching(inv, catalog)
            establishes = _matching(just, catalog) - invalidators
            if not invalidators or not establishes:
                continue
            subject = _stems(just)
            if goal_verb:
                subject |= _stems(goal_verb)
            out.append(Invalidation(establishes, invalidators,
                                    frozenset(subject), clause.strip()))
            break
        else:
            m = _LIVE.match(clause.strip())
            if not m:
                continue
            named = _matching(m.group("subj"), catalog)
            invalidators = frozenset(
                t for t in named
                if any(p in _MUTATING for p in re.split(r"[^a-z0-9]+", t.lower())))
            establishes = named - invalidators
            if not invalidators or not establishes:
                continue
            subject = _stems(m.group("just"))
            if goal_verb:
                subject |= _stems(goal_verb)
            out.append(Invalidation(establishes, invalidators,
                                    frozenset(subject), clause.strip()))
    return out


@dataclass
class FreshnessLedger:
    """Refuse an action spending a justification an invalidator has poisoned."""

    invalidations: list[Invalidation] = field(default_factory=list)
    _poisoned: set[int] = field(default_factory=set)

    def observe(self, tool: str, verb: str = "") -> None:
        """Record an ALLOWED call. Poison on an invalidator, clear on a re-establish.

        Called only from the broker's allow path. A refused invalidator never
        happened, so it must not poison anything, and a refused re-establishment
        must not clear: the precedence rung shipped with exactly the second bug.

        **A consuming call never clears**, even when its name matches the
        justification, because `pay_with_approval` and `execute_with_approval`
        name the approval they SPEND. Without that split the rule either latches,
        refusing the re-approval that should clear it, or clears itself on the
        very action it was meant to refuse.
        """
        consuming = str(verb).lower() in _CONSUMING
        for i, rule in enumerate(self.invalidations):
            if tool in rule.invalidators:
                self._poisoned.add(i)
            elif tool in rule.establishes and not consuming:
                self._poisoned.discard(i)

    def check(self, tool: str, verb: str) -> tuple[bool, str]:
        for i in sorted(self._poisoned):
            rule = self.invalidations[i]
            if rule.consumes(tool, verb):
                return False, (
                    f"{tool!r} spends a justification that "
                    f"{sorted(rule.invalidators)} invalidated and nothing has "
                    f"re-established; the sealed goal states {rule.source!r}")
        return True, ""
