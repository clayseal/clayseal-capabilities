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


#: "only on partner-api", "to the regulated path only". A permitted destination
#: is often a bare service name with no dot in it, which `_DESTINATION` cannot
#: see because it requires a TLD or a slash. Missing the sink a goal explicitly
#: permits turns the flow tier into a rule that refuses the sanctioned use.
_NAMED_SINK = re.compile(
    r"\bonly\s+(?:on|to|via|through|into)\s+(?P<a>[\w][\w.-]{2,})"
    r"|\b(?:on|to|via|through|into)\s+(?P<b>[\w][\w.-]{2,})\s+only\b",
    re.IGNORECASE)


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
    for m in _NAMED_SINK.finditer(goal or ""):
        name = (m.group("a") or m.group("b") or "").rstrip(".")
        if name and name not in seen:
            seen.append(name)
    return tuple(seen)


def derive(scen) -> SensitivityPolicy:
    """The declaration a scenario would carry if its author had written one."""
    return SensitivityPolicy(
        sensitive=("*",),
        declassified_sinks=sinks_named_by(scen.user_prompt),
    )


#: Words that make a tool sensitive BY ITS OWN NAME. The catalogue is trusted
#: configuration, fixed with the mandate and ahead of any untrusted content, so
#: a tool called `fetch_credential` returns credentials whatever the goal says.
#: This is the scoping `derive` lacks: marking every read sensitive also marks
#: `load_policy`'s prose, and that is what collapses benign completion.
_SENSITIVE_TOOL = frozenset({
    "secret", "secrets", "credential", "credentials", "key", "keys", "token",
    "password", "passwords", "pii", "private", "confidential", "privileged",
    "salary", "medical", "ssn", "personal", "sensitive", "vault",
})


def sensitive_tools(scen) -> tuple[str, ...]:
    """Tools whose own name says their output is confidential."""
    catalog = sorted(getattr(scen.make_broker(), "allowed_tools", None) or ())
    out = []
    for tool in catalog:
        parts = {p for p in re.split(r"[^a-z0-9]+", tool.lower()) if p}
        if parts & _SENSITIVE_TOOL:
            out.append(f"mcp:tool:{tool}")
    return tuple(out)


def _resolve_sinks(names, catalog) -> tuple[str, ...]:
    """Turn a destination the goal NAMES into something the tier can match.

    A permitted destination is often the tool itself: "only on partner-api" over
    a catalogue holding `call_partner_api`. The tier compares sinks against the
    resource id, so a bare name never matches and the sanctioned use is refused
    while the attack it was meant to permit stays contained. Names are resolved
    against the catalogue on a separator-insensitive containment test, exactly as
    the other rungs resolve a goal phrase to a tool.
    """
    def flat(x: str) -> str:
        return re.sub(r"[^a-z0-9]", "", x.lower())

    out = list(names)
    for name in names:
        for tool in catalog:
            if flat(name) and flat(name) in flat(tool):
                resource = f"mcp:tool:{tool}"
                if resource not in out:
                    out.append(resource)
    return tuple(out)


#: Payload shapes that carry something confidential ON THEIR FACE, for the reads
#: a name-based scope cannot see: `read_matter_note` returning privileged legal
#: strategy, `read_customer` returning an SSN.
#:
#: Every marker requires a VALUE and not a mention. A policy document that says
#: "must not contain secrets from read_secret" is prose about secrets, and
#: marking the first read of the session sensitive is precisely what collapsed
#: completion under `sensitive=("*",)`. The uppercase marker is forced
#: case-sensitive with `(?-i:...)`, because under a global IGNORECASE it matched
#: `read_secret` and reintroduced that exact failure.
_CONTENT_MARKERS = (
    r"\b(?:ssn|dob|password|passwd|api[_-]?key|credential|secret|token)\s*[=:]\s*\S",
    r"\bsecret[A-Za-z0-9_-]*\d[A-Za-z0-9_-]*\b",
    r"(?-i:\b[A-Z][A-Z0-9_]{3,}_(?:CONFIDENTIAL|SECRET|PRIVILEGED)\b)",
    # NOT a bare email address. It fires on 76 benign payloads across 12
    # scenarios here, because ordinary business traffic is full of addresses, and
    # an address is not confidential for being an address. Including it cost 12
    # benign tasks and bought nothing.
    r"\b\d{3}-\d{2}-\d{4}\b",
    r"\bpii\s*=\s*true\b",
    r"://[^\s:/]+:[^\s@/]+@",
)


def derive_scoped(scen) -> SensitivityPolicy:
    """Sensitivity scoped to the tools that declare themselves confidential.

    `derive` above is the broadest declaration expressible and it is
    net-negative: it contains 22 more attacks and loses 53 benign tasks, because
    every read becomes secret and every write becomes a leak. The falsifier it
    stated in advance fired.

    This narrows the sensitive set to tools naming a confidential thing, which
    is a property of the catalogue and not of the trajectory. Where no tool
    declares itself, the returned policy is INACTIVE and the tier behaves
    exactly as it did before, so scoping can only ever cost what it earns.
    """
    broker = scen.make_broker()
    catalog = sorted(getattr(broker, "allowed_tools", None) or ())
    # Read the SEALED GOAL SUMMARY as well as the task text. The summary is what
    # every other goal-derived rung reads, it is sealed at the same moment, and
    # it is where a permitted destination is actually stated: the task text for
    # `token-passthrough-audience` never names partner-api, while its goal says
    # "Use partner token only on partner-api". Deriving sensitivity from one and
    # sinks from the other refuses the use the goal explicitly permits.
    summary = getattr(getattr(broker, "goal", None), "summary", "") or ""
    named = sinks_named_by(f"{scen.user_prompt}\n{summary}")
    return SensitivityPolicy(
        sensitive=sensitive_tools(scen),
        declassified_sinks=_resolve_sinks(named, catalog),
        # `content_markers=_CONTENT_MARKERS` is deliberately NOT passed. It was
        # built, measured and refuted: see `flow_content_classifier.md`. It marks
        # the right reads and buys nothing, because the benign twin handles the
        # same confidential data legitimately and the two differ in WHERE the
        # value goes. The classifier answers "what is sensitive" and the binding
        # constraint is the sink policy.
    )
