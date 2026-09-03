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

Only an argument whose name is akin to the intent key or to the tool's own name:
`pay_vendor(vendor=...)` under a `vendors` list. Matching is by shared prefix and
not by exact token, so a plural key still governs a singular argument on a tool
named after something else. Checking every string argument would refuse a memo
field that happens to name a third party, and a rule that refuses the memo is a
rule an operator turns off.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from clayseal.capabilities.freshness import _akin
from clayseal.capabilities.obligations import _tokens

#: Slot words that name the SAME KIND of entity. A `vendors` list governs a
#: `beneficiary` argument because both name the party being paid, and it must
#: NOT govern an email `to`, because a payee list is not a recipient list.
#:
#: This is the mapping that "check every string argument" lacks. Widening to all
#: non-free-text arguments was tried and refused exactly one benign call,
#: `send_email(to=...)` under a vendors list, which is the whole objection: the
#: gap is not that too few slots are checked, it is that slot and list have to
#: be the same KIND. The families are fixed configuration, written here and not
#: read from anything an attacker influences.
_KINDS: tuple[frozenset[str], ...] = (
    frozenset({"vendor", "vendors", "payee", "payees", "supplier", "suppliers",
               "counterparty", "counterparties", "beneficiary", "beneficiaries",
               "merchant", "creditor", "remittee"}),
    frozenset({"recipient", "recipients", "addressee", "contact", "contacts",
               "mailbox"}),
    frozenset({"account", "accounts", "iban", "wallet", "ledger"}),
    frozenset({"repo", "repos", "repository", "repositories", "project"}),
)


def _kin_words(key: str) -> frozenset[str]:
    """The slot family a binding key belongs to, or just the key itself."""
    for family in _KINDS:
        if any(_akin(k, w) for k in _tokens(key) for w in family):
            return family
    return frozenset()


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


#: Structural fields of the intent envelope. These name the SHAPE of the task,
#: not the counterparties it may touch, so none of them is an entity list.
#:
#: This started as `{"verbs"}` alone, on the rule "everything else that is a
#: list of strings is an entity list". That rule is wrong in the dangerous
#: direction, and connecting the rung to `DeployableStack.from_goal` is what
#: surfaced it: every MCP fixture ships `structured_intent={"kind":..., "verbs":
#: [...], "tools": [...]}`, so `tools` became an entity binding with
#: `declared=True`, which is the provenance level that DENIES rather than
#: escalating. The tool allow-list then governed argument slots of kind "tool"
#: and refused benign work. One false block in nine on `mcp_attack`.
#:
#: An allow-list of entity keys would be the tighter design and it cannot be
#: written: the whole point of the rung is that an operator names their own
#: entity families. So the exclusion is explicit, and a key that is not the
#: envelope's own vocabulary is still treated as an entity list.
_ENVELOPE_FIELDS = frozenset({
    "verbs", "tools", "kind", "type", "phases", "call_templates",
    "ontology", "goal_conditions", "initial_facts", "named_objects",
    "allow_resources", "allow_agent_memory_writes", "allow_writes", "mutating",
})


def bindings_from_intent(structured_intent: Any) -> list[EntityBinding]:
    """Entity lists the sealed goal states in structured form.

    The intent envelope's own structural fields are excluded (`_ENVELOPE_FIELDS`):
    they name actions, tools and plan shape, and the envelope already owns them.
    Everything else that is a list of strings is an entity list.
    """
    out: list[EntityBinding] = []
    if not isinstance(structured_intent, dict):
        return out
    for key, values in structured_intent.items():
        if key in _ENVELOPE_FIELDS or not isinstance(values, (list, tuple, set)):
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
        want = _tokens(binding.key) | _tokens(tool) | _kin_words(binding.key)
        out = []
        for name, value in args.items():
            if not isinstance(value, str) or not value.strip():
                continue
            # Morphology, the same shared-prefix rule the freshness rung uses.
            # Exact token equality made this work only where the TOOL name
            # happened to carry the key's word: a `vendors` list against
            # `pay_counterparty(vendor=...)` matched nothing, and neither did
            # `transfer(to_vendor=...)`, because "vendor" and "vendors" are
            # different tokens. The suite hid it because every tool in it is
            # named after the thing it pays.
            if any(_akin(t, w) for t in _tokens(str(name)) for w in want):
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
