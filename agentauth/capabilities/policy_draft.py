"""Turn a written business rule into a policy draft a person then reviews.

WHY THIS EXISTS

Measured on eleven independently-authored corpora, **0 of 520 tasks declare a
budget**, and containment splits 83.3% against 18.9% on whether the grant
expresses the constraint
(`benchmarks/results/bpl_label_free.md`). The rung that matters is inert whenever
nobody writes a ceiling.

But organisations DO write their ceilings down. They are in delegation-of-
authority matrices, AP policies, SOPs and compliance manuals, in sentences like
"a single vendor payment must not exceed $10,000". They are simply not in a form
a gateway can read. This is the bridge, and it is the difference between asking an
operator to invent a policy and asking them to confirm one they already have.

IT DRAFTS. IT IS NEVER THE AUTHORITY.

The output is a **file a human reads, edits and commits**, never a live grant.
That is not process for its own sake, it is the only safe reading: whoever
controls the source document would otherwise control the grant, and a document is
exactly the kind of artefact that gets edited by people who are not thinking about
an agent's authority. `clayseal policy draft` writes YAML to disk and stops.
Nothing here is wired to the runtime.

Three properties make the draft reviewable rather than merely plausible:

**Every rule cites its source line.** A reviewer checks the YAML against the
sentence it came from, by line number, without re-reading the document.

**Nothing rule-shaped is dropped silently.** A sentence that looks like a
constraint and did not translate is emitted as a `TODO` comment with its text.
The failure mode this exists to prevent is a draft that looks complete: a rule
that vanished in translation is worse than one that was never attempted, because
the reviewer has no way to notice.

**The deterministic reader runs first and alone by default.** An optional model
may propose rules for sentences the patterns missed, and its output is marked
`source: inferred` so a reviewer knows which lines a person can verify against the
document and which they cannot.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from agentauth.capabilities.policy_scaffold import (
    Catalog,
    paths_block,
    tools_block,
    tracked_block,
)

#: Periods a written rule uses, in seconds. `per transaction` and `per payment`
#: are deliberately absent: they bound a single call, which is a ceiling and not
#: a window, and mapping them to a window would silently widen the rule.
PERIODS: dict[str, int] = {
    "hour": 3600, "hourly": 3600,
    "day": 86400, "daily": 86400, "24 hours": 86400, "24h": 86400,
    "week": 604800, "weekly": 604800,
    "month": 2592000, "monthly": 2592000,
    "quarter": 7776000,
    "year": 31536000, "annually": 31536000, "annual": 31536000,
}

_MONEY = re.compile(r"[$£€]\s?([\d,]+(?:\.\d{1,2})?)|\b([\d,]{4,}(?:\.\d{1,2})?)\s*(?:USD|EUR|GBP)\b")
_COUNT = re.compile(r"\bno more than\s+(\d{1,5})\b|\bup to\s+(\d{1,5})\s+(?!.*[$£€])", re.IGNORECASE)
# `\b` cannot anchor before `*`, which is not a word character, so a rule about
# `*.ledger` matched nothing at all until the anchor was dropped.
_PATH = re.compile(r"(?:under|within|in)\s+([~/][\w./*-]+)|([\w./-]*\*\.\w+)")
_DOMAIN = re.compile(r"\b(?:at|to|@)\s*([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", re.IGNORECASE)

#: A sentence containing one of these is making a rule. If nothing was extracted
#: from it, it becomes a TODO rather than disappearing.
RULE_MARKERS = (
    "must not", "may not", "must never", "shall not", "may only", "must only",
    "limited to", "not exceed", "no more than", "requires approval",
    "prohibited", "is not permitted", "only be", "once only", "at most",
    # A confinement is written as `only` AFTER the verb rather than before it,
    # and reading only the `may only` form dropped "may read and write only
    # under /finance/ap/" from a document whose other five rules all landed.
    "only under", "only in ", "only within", "only from", "only to",
    "restricted to", "confined to", "solely within",
    # Measured on four tau2-bench policy documents, 460 lines of prose nobody
    # here wrote: 61 sentences state a rule, the markers above caught 10 of
    # them, and 51 were dropped with no TODO at all. That is the one failure
    # this module exists to prevent, and it held only because the document it
    # was built against happened to be written in these words.
    #
    # Real policy says `cannot`, `can only`, and above all it says `if`. The
    # markers below are what those documents actually use. They widen the TODO
    # net rather than the rule net, which is the safe direction: a TODO asks a
    # reviewer a question, and a missing line asks nobody anything.
    "cannot", "can not", "can only", "can never", "should not", "should never",
    "not allowed", "not be allowed", "is not possible", "are not able",
    "never be", "must be", "has to be", "have to be", "only if", "only when",
    "not modify", "not change", "not cancel", "not exceed", "unless",
    # The residual after the markers above was almost entirely POSITIVE
    # obligation rather than prohibition: "the agent must first obtain the user
    # id", "before taking any action that updates the database, you must list".
    # Those are ordering rules, and an ordering rule is a real constraint that
    # this layer does express, as a required predecessor phase. Reading only
    # prohibitions meant a whole class of enforceable policy was invisible.
    "must ", "must,", "needs to", "need to", "is required", "are required",
    "before taking", "before calling", "first obtain", "should first",
    # The last two on those documents, and both are ordinary policy English:
    # a negative property of an object ("is not refundable") and a conditional
    # check ("if a user is traveling outside their home network, you should
    # check"). Neither carries any marker above.
    "is not ", "are not ", "you should check", "should check",
)

#: Words naming a period so `_period_in` does not read "$10,000 payment" as one.
_PERIOD_RE = re.compile(
    r"\bper\s+(\w+(?:\s+\w+)?)|\b(?:in\s+any|within\s+a|each)\s+(?:rolling\s+)?(\d*\s*\w+)\b",
    re.IGNORECASE)


@dataclass
class Rule:
    """One extracted constraint, with the line that produced it."""

    kind: str                 # value | calls | identity | egress | paths | manual
    line_no: int
    source: str               # the sentence, verbatim
    payload: dict[str, Any] = field(default_factory=dict)
    origin: str = "extracted"  # extracted | inferred

    def cite(self) -> str:
        return f"line {self.line_no}: {' '.join(self.source.split())[:96]}"


@dataclass
class Draft:
    rules: list[Rule] = field(default_factory=list)
    unmapped: list[Rule] = field(default_factory=list)

    def summary(self) -> str:
        kinds: dict[str, int] = {}
        for rule in self.rules:
            kinds[rule.kind] = kinds.get(rule.kind, 0) + 1
        parts = ", ".join(f"{k}={v}" for k, v in sorted(kinds.items()))
        return (f"{len(self.rules)} rule(s) extracted [{parts}], "
                f"{len(self.unmapped)} sentence(s) left for a person")


def _money(text: str) -> str | None:
    match = _MONEY.search(text)
    if not match:
        return None
    raw = match.group(1) or match.group(2)
    return raw.replace(",", "") if raw else None


def _period_in(text: str) -> int | None:
    # LONGEST key first, always. "24 hours" contains "hour", and matching the
    # short one first read a daily cap as an hourly one, which is a rule
    # twenty-four times tighter than the document says.
    ordered = sorted(PERIODS.items(), key=lambda kv: -len(kv[0]))
    for match in _PERIOD_RE.finditer(text):
        phrase = (match.group(1) or match.group(2) or "").strip().lower()
        for name, seconds in ordered:
            if name in phrase:
                return seconds
    low = text.lower()
    for name, seconds in ordered:
        if re.search(rf"\b(?:per|any|each|every)\s+(?:rolling\s+)?{re.escape(name)}\b", low):
            return seconds
    return None


#: "X only if the status is pending", "cannot be Y-ed if it has already been
#: flown". The condition is what follows the connective; the tools it applies to
#: come from the catalog, which is why `extract` takes one.
_CONDITION = re.compile(
    r"\b(?:only\s+(?:be\s+)?\w+\s+)?(if|when|unless|once)\s+"
    r"(?:its?\s+|the\s+|any\s+)?"
    r"([a-z][a-z_ ]{2,28}?)\s+(?:is|are|was|were|(?:has|have)\s+"
    r"(?:already\s+|not\s+)?been)\s+"
    r"['\"]?([a-z][a-z_-]{1,24})['\"]?",
    re.IGNORECASE)

#: "must first obtain the user id", "before taking any action ... you must list".
_ORDERING = re.compile(
    r"\b(?:must|should|needs? to)\s+(?:first\s+|also\s+)?"
    r"(obtain|list|check|verify|confirm|get|retrieve|look up|read)\b",
    re.IGNORECASE)

#: A negated rule: the condition names the state in which the tool is FORBIDDEN.
_NEGATED = re.compile(r"\b(cannot|can not|may not|must not|shall not|"
                      r"is not|are not|never)\b", re.IGNORECASE)


#: "An order can only be cancelled ...", "The reservation cannot be changed ...".
#: The subject is what the rule is ABOUT, and a tool that does not mention it is
#: doing the same verb to a different thing.
_SUBJECT = re.compile(
    r"^\W*(?:an?|the|each|every|all)\s+([a-z][a-z_]{2,20})\b", re.IGNORECASE)


def _subject_of(line: str) -> str | None:
    match = _SUBJECT.match(line.strip())
    if match is None:
        return None
    word = match.group(1).lower().rstrip("s")
    return word if len(word) > 2 else None


def _tools_named(line: str, catalog: Iterable[str]) -> list[str]:
    """Tools whose name, or whose name read as words, appears in the sentence.

    A rule says "cancelled" and the tool is `cancel_order`, so the match is on
    the stem rather than the exact name. Nothing is guessed beyond the catalog:
    a tool that is not granted cannot be withdrawn, and `tools.when` refuses one
    that reaches outside the grant.
    """
    low = line.lower()
    # A rule about an ORDER must not bind a tool about a USER just because both
    # say "modify". Measured on tau2 retail: "An order can only be modified if
    # its status is pending" bound `modify_user_address`, and eleven of that
    # domain's own ground-truth actions were refused by a rule that was never
    # about them. Where the sentence names its subject, a tool has to mention it.
    subject = _subject_of(line)
    out: list[str] = []
    for tool in catalog or ():
        if subject and subject not in str(tool).lower():
            continue
        words = [w for w in str(tool).lower().replace("-", "_").split("_") if w]
        if not words:
            continue
        stem = words[0]
        stems = {stem, stem.rstrip("e") + "ed", stem + "ed", stem + "led",
                 stem.rstrip("y") + "ied", stem + "ling", stem + "ing"}
        if any(re.search(rf"\b{re.escape(s)}", low) for s in stems):
            out.append(str(tool))
    return out


def extract(document: str, tools: Iterable[str] | None = None) -> Draft:
    """Read a document into a draft. Deterministic, no model, no network.

    `tools` is the catalog, which is what makes the two large rule classes
    extractable at all. Measured on four `tau2-bench` policy documents, ordering
    is 36% of the rules that state a constraint and state-conditional
    prohibition is 31%, and both bind a rule to a TOOL: "an order can only be
    cancelled while pending" is about `cancel_order`. Without a catalog there is
    nothing to bind to and the sentence can only become a TODO, which is what it
    did. `clayseal policy init --rules` already has both halves.
    """
    catalog = list(tools or ())
    draft = Draft()
    for line_no, raw in enumerate(document.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        low = line.lower()
        if not any(marker in low for marker in RULE_MARKERS):
            continue

        found_here: list[Rule] = []
        found_here.extend(_conditional_rules(line, line_no, catalog))
        amount = _money(line)
        period = _period_in(line)
        count = None
        count_match = _COUNT.search(line)
        if count_match:
            count = count_match.group(1) or count_match.group(2)

        # A ceiling on an amount. "in aggregate", "total" and a period all point
        # at a cumulative limit; without them it bounds one call.
        if amount is not None:
            aggregate = period is not None or any(
                w in low for w in ("total", "aggregate", "cumulative", "combined"))
            found_here.append(Rule(
                kind="value", line_no=line_no, source=line,
                payload={"ceiling": amount, "window_seconds": period,
                         "per_call": not aggregate,
                         "needs_approval_above": "requires approval" in low}))

        # A ceiling on a count, but not when the number was the money.
        if count is not None and (amount is None or count != amount):
            found_here.append(Rule(
                kind="calls", line_no=line_no, source=line,
                payload={"ceiling": int(count), "window_seconds": period}))

        if any(w in low for w in ("once only", "once per", "paid once",
                                  "duplicate", "only once")):
            found_here.append(Rule(kind="identity", line_no=line_no, source=line,
                                   payload={}))

        domains = [d for d in _DOMAIN.findall(line) if "." in d]
        if domains and any(w in low for w in ("sent to", "send", "only be", "may only")):
            found_here.append(Rule(
                kind="egress", line_no=line_no, source=line,
                payload={"domains": sorted(set(domains)),
                         "deny": "must not" in low or "may not" in low}))

        # A path at the end of a sentence carries the full stop, and the
        # trailing `.` survives into the glob as a directory component:
        # `/finance/ap/.` became `/finance/ap/./**`, which matches nothing the
        # rule meant. Sentence punctuation is never part of a path.
        paths = [p.rstrip(".,;:)") for pair in _PATH.findall(line)
                 for p in pair if p]
        paths = [p for p in paths if p not in ("", "/", "~")]
        if paths:
            found_here.append(Rule(
                kind="paths", line_no=line_no, source=line,
                payload={"paths": sorted(set(paths)),
                         "deny": any(w in low for w in
                                     ("never", "must not", "may not", "prohibited"))}))

        if found_here:
            draft.rules.extend(found_here)
        else:
            # Rule-shaped and untranslated. It goes in the output as a TODO
            # rather than vanishing, because a draft that looks complete is the
            # failure this module exists to prevent.
            draft.unmapped.append(Rule(kind="manual", line_no=line_no, source=line))
    return draft


def to_yaml(draft: Draft, *, goal_id: str = "REPLACE-ME",
            goal_summary: str = "REPLACE ME with the task this grant is for",
            tools: list[str] | None = None,
            catalog: Catalog | None = None,
            document: str | None = None,
            server: str | None = None) -> str:
    """Render a draft as a reviewable policy document.

    Two sources, and neither is authority. The document says what the
    organisation permits and cannot know what the tools are called. The server's
    catalog says what the tools are called and is written by the party being
    constrained. Rendering both here rather than in two files is deliberate: the
    section where they meet, `budgets.tracked`, is the one an operator gets
    wrong, and it is only checkable with both halves in front of them.

    Deliberately not machine-perfect. Placeholders are loud, every rule carries
    the line it came from, and unmapped sentences are TODO comments, because the
    next step is a person reading this next to the source.
    """
    provenance = ["# NOT a grant until a person has reviewed it."]
    if document:
        provenance.append(f"# Rules read from the document: {document}")
    if server:
        provenance.append(f"# Tools read from the catalog of: {server}")
        provenance += [
            "# That catalog is written by the server this policy constrains, so",
            "# every effect below is a guess and none of it is authority. A",
            "# description may raise a tool's effect here and never lower it.",
        ]
    out: list[str] = [
        "# DRAFT policy, generated by `clayseal policy "
        + ("init" if server else "draft") + "`.",
        "#",
        *provenance,
        "# Every rule below cites the line of the source document it came from;",
        "# check them against the document before this is used for anything.",
        "# Then run:",
        "#",
        "#     clayseal policy lint <this file>",
        "#",
        f"# {draft.summary()}",
        "",
        "version: 1",
        "",
        "goal:",
        f"  id: {goal_id}",
        "  summary: >-",
        f"    {goal_summary}",
        "",
        "profile: supervised",
        "",
        "# TODO: set an expiry. A grant with none authorises forever.",
        "# expires_at: 2027-01-01T00:00:00Z",
        "",
    ]

    tool_list = tools or []
    out += ["tools:"]
    if catalog is not None:
        out += tools_block(catalog)
    elif tool_list:
        out += [f"  allow: [{', '.join(sorted(tool_list))}]",
                "  # TODO: declare each tool's effect and mark the harmless ones.",
                "  # effects:  {pay_vendor: transfer, send_email: send}",
                "  # harmless: []"]
    else:
        out += ["  # TODO: list the tools this agent may reach. Without it, any",
                "  #       tool it can call is in scope.",
                "  allow: []"]
    out.append("")

    conditionals = [r for r in draft.rules
                    if r.kind in ("ordering", "conditional")]
    if conditionals:
        out += [
            "  # Rules about ORDER and STATE, which no ceiling can express and",
            "  # which are the two largest classes in a real policy document.",
            "  # Each WITHDRAWS from tools.allow above and can never add to it.",
            "  when:",
        ]
        for rule in conditionals:
            out.append(f"    # {rule.cite()}")
            deny = ", ".join(sorted(rule.payload["deny"]))
            if rule.kind == "ordering":
                requires = ", ".join(sorted(rule.payload["requires"]))
                out.append(f"    - requires: [{requires}]")
            else:
                key = "if" if "if" in rule.payload else "unless"
                condition = rule.payload[key]
                rendered = ", ".join(f"{k}: {v}" for k, v in condition.items())
                out.append(f"    - {key}: {{{rendered}}}")
            out.append(f"      deny: [{deny}]")
            # The citation travels into the runtime, so a refusal names the line
            # of the document it came from rather than a fact dictionary.
            cite = " ".join(rule.source.split())[:88].replace('"', "'")
            out.append(f'      reason: "line {rule.line_no}: {cite}"')
            if rule.kind != "ordering":
                out.append("      # CHECK the fact name against what the tool "
                           "actually returns.")
        out.append("")

    paths = [r for r in draft.rules if r.kind == "paths"]
    catalog_paths = paths_block(catalog) if catalog is not None else []
    if paths or catalog_paths:
        allow = [p for r in paths if not r.payload["deny"] for p in r.payload["paths"]]
        deny = [p for r in paths if r.payload["deny"] for p in r.payload["paths"]]
        out.append("paths:")
        for rule in paths:
            out.append(f"  # {rule.cite()}")
        if allow:
            out.append(f"  allow: [{', '.join(_glob(p) for p in sorted(set(allow)))}]")
        if deny:
            out.append(f"  deny:  [{', '.join(_glob(p) for p in sorted(set(deny)))}]")
        if not allow:
            out += ["  # The document named no directory to confine this to.",
                    "  # Without an allow list any path these tools accept is",
                    "  # in scope, and a deny list only closes what it names.",
                    "  # allow: []"]
        if catalog_paths:
            out += catalog_paths
        else:
            out += ["  # TODO: name the argument each tool carries its path in, or the",
                    "  #       scope cannot be applied to it. See docs/POLICY.md.",
                    "  # arg_names: {}"]
        out.append("")

    egress = [r for r in draft.rules if r.kind == "egress" and not r.payload["deny"]]
    if egress:
        out.append("egress:")
        for rule in egress:
            out.append(f"  # {rule.cite()}")
        allowed = sorted({d for r in egress for d in r.payload["domains"]})
        out.append(f"  domains: [{', '.join(allowed)}]")
        out.append("  bind_recipients: true")
        out.append("")

    value = [r for r in draft.rules if r.kind == "value"]
    calls = [r for r in draft.rules if r.kind == "calls"]
    identity = [r for r in draft.rules if r.kind == "identity"]
    if value or calls:
        out.append("budgets:")
    if value:
        out.append("  value:")
        out.append("    ceilings:")
        windows: list[str] = []
        for i, rule in enumerate(value, start=1):
            out.append(f"      # {rule.cite()}")
            if rule.payload["per_call"]:
                out.append("      # NOTE: this reads as a per-CALL limit, which a")
                out.append("      #       cumulative ceiling does not express. A")
                out.append("      #       session ceiling here is TIGHTER than the")
                out.append("      #       rule, not looser. Confirm which you want.")
            if rule.payload["needs_approval_above"]:
                out.append("      # NOTE: the document says approval is required above")
                out.append("      #       this, which is a step-up and not a ceiling.")
                out.append("      #       A ceiling REFUSES; step-up asks. See SECURITY.md.")
            out.append(f'      budget_{i}: "{rule.payload["ceiling"]}"')
            if rule.payload["window_seconds"]:
                windows.append(f'budget_{i}: {rule.payload["window_seconds"]}')
        if windows:
            out.append(f"    windows: {{{', '.join(windows)}}}")
        out += ["    tracked:"]
        if catalog is not None:
            out += tracked_block(
                catalog, budgets=[f"budget_{i}" for i in range(1, len(value) + 1)])
        else:
            out += ["      # TODO: map each tool to the budget it debits and the",
                    "      #       argument carrying the amount.",
                    "      # pay_vendor: {arg: amount, budget: budget_1}"]
        if identity:
            for rule in identity:
                out.append(f"      # {rule.cite()}")
            out += ["      #       ... and add `identity: [invoice, period]` to the",
                    "      #       tool that rule applies to."]
    if calls:
        out.append("  calls:")
        out.append("    ceilings:")
        windows = []
        for i, rule in enumerate(calls, start=1):
            out.append(f"      # {rule.cite()}")
            out.append(f"      count_{i}: {rule.payload['ceiling']}")
            if rule.payload["window_seconds"]:
                windows.append(f"count_{i}: {rule.payload['window_seconds']}")
        if windows:
            out.append(f"    windows: {{{', '.join(windows)}}}")
        out += ["    tracked:",
                "      # TODO: map each tool to the count budget it debits.",
                "      # issue_refund: count_1"]

    denied_egress = [r for r in draft.rules if r.kind == "egress" and r.payload["deny"]]
    leftovers = draft.unmapped + denied_egress
    if leftovers:
        out += ["", "# ---------------------------------------------------------",
                "# NOT TRANSLATED. Each of these reads as a rule and none of them",
                "# became policy above. They are here because a draft that looks",
                "# complete is worse than one that admits what it dropped.",
                "# ---------------------------------------------------------"]
        for rule in leftovers:
            out.append(f"# TODO  {rule.cite()}")
    return "\n".join(out) + "\n"


def _conditional_rules(line: str, line_no: int, catalog: list[str]) -> list[Rule]:
    """Ordering and state-conditional rules, bound to tools from the catalog."""
    if not catalog:
        return []
    subjects = _tools_named(line, catalog)
    if not subjects:
        return []
    out: list[Rule] = []

    ordering = _ORDERING.search(line)
    if ordering:
        prerequisites = [t for t in catalog
                         if t.lower().startswith(
                             ordering.group(1).lower().split()[0])]
        targets = [t for t in subjects if t not in prerequisites]
        if prerequisites and targets:
            out.append(Rule(kind="ordering", line_no=line_no, source=line,
                            payload={"requires": prerequisites,
                                     "deny": targets}))

    condition = _CONDITION.search(line)
    if condition and not out:
        connective, fact, value = (condition.group(1).lower(),
                                   condition.group(2).strip().replace(" ", "_"),
                                   condition.group(3).lower())
        negated = bool(_NEGATED.search(line[:condition.start()]))
        # "cannot X if Y" withdraws WHEN the condition holds; "only X if Y"
        # withdraws UNLESS it holds. Reading one as the other inverts the rule,
        # so a sentence that supports neither reading clearly is left alone.
        if negated or connective == "once":
            key, form = "if", "when this holds"
        # `only` sits INSIDE the match ("can only be cancelled if ..."), so a
        # prefix-only check never saw it and every "only if" rule was dropped.
        elif "only" in line.lower()[:condition.end()] or connective == "unless":
            key, form = "unless", "unless this holds"
        else:
            return out
        out.append(Rule(kind="conditional", line_no=line_no, source=line,
                        payload={key: {fact: value}, "deny": subjects,
                                 "form": form}))
    return out


def _glob(path: str) -> str:
    """A directory rule means everything under it."""
    if path.endswith("/"):
        return f'"{path}**"'
    if "*" in path:
        return f'"{path}"'
    return f'"{path}/**"'
