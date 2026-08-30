"""Which counterparty, not which host: entity binding from the sealed goal.

`EgressPolicy` answers "may this session reach `acme-internal.com`". Several
business rules are not about a host at all, they are about *which entity*:

    "Pay Acme and Beta only"

The gateway already holds that list. `trusted-followup-goal-drift` seals
`structured_intent={"verbs": [...], "vendors": ["Acme", "Beta"]}` and then pays
`ContingencyCo`, because nothing reads the vendor list back out. That is not an
inference problem; it is a declared constraint with no enforcement point.

TWO SOURCES, TWO VERDICTS

* **Declared.** `goal.structured_intent` carries a named list. It is part of the
  sealed goal, fixed before untrusted content exists, and it says exactly which
  values are permitted. Paying outside it is a fact, and a fact may DENY.

* **Derived.** The summary says `"Pay Acme and Beta only"` and no structured
  list exists. Reading entity names out of a sentence is inference: `"Acme"` may
  be the registered name, a trade name, or a prefix of a longer one, which is
  what `semantic-payee-resolve` exists to punish. It escalates and never denies.

WHICH ARGUMENT CARRIES THE ENTITY

Only an argument whose name shares a token with the intent key or with the
tool's own name: `pay_vendor(vendor=...)` under a `vendors` list. Checking every
string argument would refuse a memo field that happens to name a third party,
and a rule that refuses the memo is a rule an operator turns off.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from clayseal.capabilities.obligations import _tokens

#: "<verb> <A> and <B> only", the form a policy sentence actually uses.
_ONLY = re.compile(
    r"^(?P<verb>[a-z]+)\s+(?P<names>[A-Z][\w'&-]*(?:(?:,\s*|\s+and\s+)[A-Z][\w'&-]*)*)"
    r"\s+only\b", re.IGNORECASE)


def _norm(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


@dataclass(frozen=True)
class EntityBinding:
    """Values permitted for a named argument, and where the list came from."""

    key: str
    allowed: frozenset[str]
    declared: bool
    source: str

    def describe(self) -> str:
        kind = "declared" if self.declared else "derived"
        return f"{self.key}: {sorted(self.allowed)} ({kind} from {self.source!r})"


def bindings_from_intent(structured_intent: Any) -> list[EntityBinding]:
    """Entity lists the sealed goal states in structured form.

    `verbs` is excluded: it names actions, and the intent envelope already owns
    it. Everything else that is a list of strings is an entity list.
    """
    out: list[EntityBinding] = []
    if not isinstance(structured_intent, dict):
        return out
    for key, values in structured_intent.items():
        if key == "verbs" or not isinstance(values, (list, tuple, set)):
            continue
        names = {_norm(v) for v in values if isinstance(v, str) and v.strip()}
        if names:
            out.append(EntityBinding(str(key), frozenset(names), True,
                                     "structured_intent"))
    return out


def derive_bindings(goal_summary: str) -> list[EntityBinding]:
    """Entity lists stated in prose. Returns nothing rather than guessing."""
    out: list[EntityBinding] = []
    for clause in re.split(r"[;.]", goal_summary or ""):
        m = _ONLY.match(clause.strip())
        if not m:
            continue
        names = {_norm(n) for n in re.split(r",\s*|\s+and\s+", m.group("names"))
                 if _norm(n)}
        if len(names) >= 1:
            out.append(EntityBinding(m.group("verb").lower(), frozenset(names),
                                     False, clause.strip()))
    return out


@dataclass
class EntityLedger:
    """Refuse an action naming an entity the sealed goal did not."""

    bindings: list[EntityBinding] = field(default_factory=list)

    def _relevant(self, binding: EntityBinding, tool: str, args: Any) -> list[str]:
        """Argument values to check: only args this binding plausibly names."""
        if not isinstance(args, dict):
            return []
        want = _tokens(binding.key) | _tokens(tool)
        out = []
        for name, value in args.items():
            if not isinstance(value, str) or not value.strip():
                continue
            if _tokens(str(name)) & want:
                out.append(value)
        return out

    def check(self, tool: str, args: Any) -> tuple[bool, str, bool]:
        """(allowed, reason, declared). `declared` picks DENY over STEP_UP."""
        for binding in self.bindings:
            for value in self._relevant(binding, tool, args):
                if _norm(value) not in binding.allowed:
                    return False, (
                        f"{value!r} is not among the entities the sealed goal "
                        f"named; {binding.describe()}"), binding.declared
        return True, "", False
