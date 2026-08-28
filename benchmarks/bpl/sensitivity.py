"""Derive a confidentiality declaration for a scenario, mechanically.

WHY THIS EXISTS

`SensitivityPolicy.active` is False when `sensitive` is empty, so the flow tier
is a no-op unless a mandate declares confidentiality classes. Measured across
BPL: **0 of 132 scenarios declare any**, so the tier is inert in every cell of
the published table, and `dataflow-taint` beats the gateway on the
confidentiality family 16 of 28 to 10 of 28 while it is switched off.

That is the same shape as the budget finding one rung over. Write the constraint
as a ceiling and the aggregate rung enforces it; write nothing and it has
nothing to accumulate against. Declare which objects are secret and where they
may go and the flow rung enforces it; declare nothing and it is inert. This
module measures what the second half of that sentence is worth.

THE DERIVATION, STATED BEFORE IT WAS MEASURED

    sensitive           ("*",) — everything this session reads is confidential.
    declassified_sinks  the destinations named in the SEALED GOAL text.

Two properties make this an experiment rather than an answer key:

**It never reads the attack.** Not `violating_script`, not `violated()`. Its
only inputs are `user_prompt`, which is the sealed goal a real deployment
compiles its envelope from, and the tool catalog. A rule derived from the
violating script would contain every attack by construction and would measure
nothing.

**It is uniform.** The identical rule is applied to all three families. The
aggregate and escape families are the placebo: a derivation that encodes
answers rather than a constraint would move them too.

The falsifier is the benign twin. `sensitive=("*",)` is deliberately the
broadest declaration expressible — every read is secret — so if this buys
containment by refusing everything, benign completion collapses and the result
is worthless. Read the two columns together or not at all.
"""
from __future__ import annotations

import re

from clayseal.capabilities.confidentiality import SensitivityPolicy

#: An email address, a bare domain, or a path-looking token.
_DESTINATION = re.compile(
    r"[\w.+-]+@[\w-]+\.[\w.-]+"          # ops@acme-internal.com
    r"|(?<![\w@.])[\w-]+\.(?:com|org|net|io|internal|example|local)\b"
    r"|(?:/|\./)[\w./-]+"                # /reports/summary.md
)


def sinks_named_by(goal: str) -> tuple[str, ...]:
    """Destinations a sealed goal names, in the order it names them.

    A real deployment gets these from the mandate, which is why they come from
    the goal text here and not from the benign trajectory. Deriving them from
    the compliant script would be close to circular: "the sinks the attacker did
    not use" is not a policy, it is the answer.
    """
    seen: list[str] = []
    for match in _DESTINATION.findall(goal or ""):
        # A sentence-ending period is not part of the address. Left in, the
        # derived sink never matches the destination the call actually carries,
        # and the experiment measures a typo instead of an idea.
        match = match.rstrip(".")
        if match and match not in seen:
            seen.append(match)
    return tuple(seen)


def derive(scen) -> SensitivityPolicy:
    """The declaration a scenario would carry if its author had written one."""
    return SensitivityPolicy(
        sensitive=("*",),
        declassified_sinks=sinks_named_by(scen.user_prompt),
    )
