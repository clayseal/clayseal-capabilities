"""A server's own tool catalog, read into the skeleton of a policy.

WHY THIS EXISTS

`policy_draft` turns a business document into rules. This turns the other half
of the integration problem into a starting point: an operator who wants to put
the gateway in front of a server they already run has to name every tool, name
each tool's effect, and name which argument carries a path, and getting any of
those wrong is silent. A tool left off `tools.allow` is denied and visible; an
argument left out of `paths.arg_names` means the path scope never reads that
tool's path at all, which looks exactly like an allow.

The server already knows all three. `tools/list` carries the names, the prose
description, and the JSON Schema of every argument. This reads that answer and
writes it out as YAML with the guesses marked.

THE CATALOG IS NOT A TRUSTED INPUT

The thing describing the tools is the thing being constrained. A compromised or
merely optimistic server can describe `wire_funds` as "reads the account
balance", so a scaffold that believed descriptions would let the constrained
party write its own constraint. Two rules keep that from mattering:

1. **The catalog may only raise a tool's effect, never lower it.** The name-based
   verb is the floor. Prose can push `call` up to `transfer`; nothing in the
   catalog can push `transfer` down to `read`. This is the same monotone rule
   the conditional ceilings and the multiplicity inferrer follow, for the same
   reason.
2. **The output is a file, not a grant.** Nothing here is wired to a runtime.
   It writes YAML to disk and stops, and `clayseal policy lint` is what a person
   runs next.

Silence is also not evidence. A tool that ships no input schema is not recorded
as having no path argument, because "the server did not say" and "the server
said no" are different facts and only one of them is safe to act on.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from clayseal.capabilities.mcp_proxy import DEFAULT_PATH_ARGS
from clayseal.capabilities.tool_verbs import classify_verb

#: How much authority a verb implies. The scaffold may move a tool up this
#: ladder on the strength of the catalog's prose and may never move it down.
VERB_RANK: dict[str, int] = {"read": 0, "call": 1, "write": 2, "send": 3,
                             "transfer": 4}

#: Prose that suggests an effect the name did not carry. Checked against the
#: description only, and only ever to raise the verb.
#:
#: These are VERBS and not topics. An earlier version listed `invoice` under
#: transfer, which read `lookup_invoice`, described as "Read one invoice
#: record", as a money-moving tool. A noun says what a tool is about; only a
#: verb says what it does.
_PROSE: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("transfer", re.compile(
        r"\b(transfers?|pays?|paid|wires?|disburses?|remits?|refunds?|"
        r"reimburses?|charges? the)\b", re.IGNORECASE)),
    ("send", re.compile(
        r"\b(sends?|emails?|notifies|notify|dispatches?|publishes? to)\b",
        re.IGNORECASE)),
    ("write", re.compile(
        r"\b(creates?|writes?|modifies|modify|updates?|deletes?|removes?|"
        r"overwrites?|provisions?|destroys?|applies|apply)\b", re.IGNORECASE)),
    # Last, and it can never win on rank. It is here so that a server
    # describing an effectful tool as read-only is DETECTED, which is the shape
    # of a catalog talking its own authority down, rather than passing silently
    # because nothing matched.
    ("read", re.compile(
        r"\b(reads?|read-only|returns?|lists?|fetches|gets?|queries|"
        r"searches|inspects?)\b", re.IGNORECASE)),
)

#: Argument names that carry a filesystem path. The proxy's defaults plus the
#: shapes a schema tends to use. A name ending in one of the suffixes counts too.
_PATH_SUFFIX = ("_path", "_dir", "_directory", "_file", "_filename", "_folder")
_PATH_EXACT = frozenset(DEFAULT_PATH_ARGS) | {
    "dir", "directory", "folder", "target", "destination", "source", "src",
    "dest", "location", "uri", "url", "key", "object_key", "prefix"}

#: Argument names that look like the magnitude of an effect, which is what a
#: value budget counts.
_AMOUNT = re.compile(
    r"^(amount|value|total|sum|price|cost|quantity|qty|count|size|limit|"
    r"balance|budget|fee|charge)(_[a-z0-9_]+)?$|_(amount|value|total|price|"
    r"cost|quantity|qty)$")

#: Argument names that identify the OBJECT an effect lands on, which is what
#: stops one invoice being paid twice through two different calls.
_IDENTITY = re.compile(
    r"^(id|uuid|key|reference|ref)$|_(id|uuid|key|reference|ref|number|no)$|"
    r"^(idempotency|invoice|order|transaction|payment|request)_")


@dataclass(frozen=True)
class ToolFacts:
    """What the catalog said about one tool, and how sure any of it is."""

    name: str
    verb: str
    verb_from: str
    schema_seen: bool
    path_args: tuple[str, ...] = ()
    amount_args: tuple[str, ...] = ()
    identity_args: tuple[str, ...] = ()
    disagreement: str | None = None
    #: The server's own prose. Read for the verb and previously discarded, which
    #: made one thing impossible: a written policy and a tool catalog use
    #: different words, and a rule about "bills" has to reach `make_payment`. A
    #: reader working from tool NAMES cannot bridge that and one working from
    #: descriptions can. Kept as evidence, never as authority: the verb rule
    #: below still only ever RAISES from prose.
    description: str = ""

    @property
    def unsure(self) -> bool:
        """True when nothing in the catalog settled what this tool does."""
        return self.verb == "call"

    @property
    def pathless(self) -> bool:
        """True only when the server SHOWED a schema with no path in it."""
        return self.schema_seen and not self.path_args


@dataclass
class Catalog:
    """A parsed `tools/list` result."""

    tools: list[ToolFacts] = field(default_factory=list)
    #: Entries the server sent that could not be read as a tool at all.
    unreadable: int = 0

    def path_args(self) -> dict[str, str]:
        """Tool to the argument that carries its path.

        Keyed by tool because that is the shape `paths.arg_names` takes, and an
        earlier version emitted a flat list, which `policy lint` refused. A tool
        whose only path-shaped argument is one the proxy already reads by
        default is left out: naming it changes nothing.
        """
        out: dict[str, str] = {}
        for tool in self.tools:
            for arg in tool.path_args:
                if arg not in DEFAULT_PATH_ARGS:
                    out[tool.name] = arg
                    break
        return out

    def descriptions(self) -> dict[str, str]:
        """Tool to the server's own prose about it, where there was any.

        A written rule and a tool catalog rarely share vocabulary: a policy
        sentence says "invoices", the tool is `make_payment`, and nothing at the
        name level connects them. The description usually does, because it is the
        one place the server explains itself in the same register the document
        was written in.
        """
        return {t.name: t.description for t in self.tools if t.description}

    def pathless(self) -> list[str]:
        return sorted(t.name for t in self.tools if t.pathless)

    def unsure(self) -> list[str]:
        return sorted(t.name for t in self.tools if t.unsure)

    def disagreements(self) -> list[ToolFacts]:
        return [t for t in self.tools if t.disagreement]


def _looks_like_path(arg: str) -> bool:
    low = arg.lower()
    return low in _PATH_EXACT or low.endswith(_PATH_SUFFIX)


def _prose_verb(description: str) -> str | None:
    for verb, pattern in _PROSE:
        if pattern.search(description):
            return verb
    return None


def read_tool(entry: object) -> ToolFacts | None:
    """Read one `tools/list` entry. Returns None if it is not a tool."""
    if not isinstance(entry, dict):
        return None
    name = entry.get("name")
    if not isinstance(name, str) or not name.strip():
        return None
    name = name.strip()

    from_name = classify_verb(name)
    description = entry.get("description")
    description = description if isinstance(description, str) else ""
    from_prose = _prose_verb(description)

    verb, verb_from, disagreement = from_name, "name", None
    if from_prose and from_prose != from_name:
        if VERB_RANK[from_prose] > VERB_RANK[from_name]:
            verb, verb_from = from_prose, "description"
        else:
            # The prose claims LESS authority than the name does. Keep the
            # name's answer and say so: this is the shape of a server talking
            # its own effect down, and it is a person's call either way.
            disagreement = (f"name reads `{from_name}`, the server's own "
                            f"description reads `{from_prose}`")

    schema = entry.get("inputSchema")
    properties = schema.get("properties") if isinstance(schema, dict) else None
    schema_seen = isinstance(properties, dict)
    args = sorted(str(k) for k in properties) if schema_seen else []

    return ToolFacts(
        name=name,
        verb=verb,
        verb_from=verb_from,
        schema_seen=schema_seen,
        path_args=tuple(a for a in args if _looks_like_path(a)),
        amount_args=tuple(a for a in args if _AMOUNT.search(a.lower())),
        identity_args=tuple(a for a in args if _IDENTITY.search(a.lower())),
        disagreement=disagreement,
        description=description,
    )


def read_catalog(result: object) -> Catalog:
    """Read the `result` of a `tools/list` response."""
    listing = result.get("tools") if isinstance(result, dict) else None
    if not isinstance(listing, list):
        return Catalog()
    catalog = Catalog()
    for entry in listing:
        tool = read_tool(entry)
        if tool is None:
            catalog.unreadable += 1
        else:
            catalog.tools.append(tool)
    catalog.tools.sort(key=lambda t: t.name)
    return catalog


def _flow(items: list[str]) -> str:
    return "[" + ", ".join(items) + "]"


def tools_block(catalog: Catalog) -> list[str]:
    """The `tools:` body, with every guess marked as one."""
    names = [t.name for t in catalog.tools]
    if not names:
        return ["  # The catalog was empty. Nothing can be allowed until this",
                "  # names the tools the task actually needs.",
                "  allow: []"]

    effects = ", ".join(f"{t.name}: {t.verb}" for t in catalog.tools)
    from_prose = any(t.verb_from == "description" for t in catalog.tools)
    out = [
        f"  allow: {_flow(names)}",
        "  # Effects GUESSED from tool names"
        + (" and descriptions" if from_prose else "")
        + ". The floor's write and egress",
        "  # rules key off these, so a wrong one is a wrong decision. Check all"
        f" {len(names)}.",
        f"  effects:  {{{effects}}}",
    ]
    unsure = catalog.unsure()
    if unsure:
        out += ["  # Neither the name nor the description settled these, so they"
                " default to",
                "  # `call`: no assumed effect, and no assumed harmlessness"
                " either.",
                f"  # UNRESOLVED: {', '.join(unsure)}"]
    for tool in catalog.disagreements():
        out.append(f"  # CHECK {tool.name}: {tool.disagreement}. Kept the"
                   " stronger reading.")
    out += ["  # TODO: list the tools that have no effect worth counting.",
            "  harmless: []"]
    return out


def paths_block(catalog: Catalog) -> list[str]:
    """The part of `paths:` a catalog can answer: which argument holds a path."""
    out: list[str] = []
    path_args = catalog.path_args()
    if path_args:
        rendered = ", ".join(f"{tool}: {arg}"
                             for tool, arg in sorted(path_args.items()))
        out += ["  # The argument each tool carries its path in, read from the"
                " input",
                "  # schemas. This is live and wrong in either direction costs"
                " something:",
                "  # a tool missing from here has its path checked against"
                " nothing, and",
                "  # an argument named here that is not a path gets checked as"
                " one.",
                f"  arg_names: {{{rendered}}}"]
    extra = sorted({a for t in catalog.tools for a in t.path_args[1:]
                    if a not in DEFAULT_PATH_ARGS})
    if extra:
        out += [f"  # {', '.join(extra)} also look like paths and only one"
                " argument per tool",
                "  # can be declared. Check which one actually decides where"
                " the write lands."]
    pathless = catalog.pathless()
    if pathless:
        out += ["  # These showed a schema with no path-shaped argument in it.",
                f"  pathless: {_flow(pathless)}"]
    silent = sorted(t.name for t in catalog.tools if not t.schema_seen)
    if silent:
        subject = "it takes" if len(silent) == 1 else "they take"
        out += [f"  # No input schema was published for {', '.join(silent)},"
                " so whether",
                f"  # {subject} a path is unknown rather than settled. Declare"
                " either way."]
    return out


def tracked_block(catalog: Catalog, *, budgets: list[str] | None = None,
                  indent: str = "      ") -> list[str]:
    """Suggested `tracked:` entries: which argument carries the amount.

    Always commented out, and the budget is never guessed. The catalog knows
    which argument carries the amount and the document knows what the ceilings
    are; which tool debits which ceiling is in neither, and it is the decision
    the whole aggregate rung rests on. Naming the wrong one splits a shared
    limit in two, or charges a refund against the payment ceiling, and both
    read as working policy.
    """
    valued = [t for t in catalog.tools if t.amount_args]
    if not valued:
        return [f"{indent}# No argument in the catalog looked like the size of"
                " an effect. If",
                f"{indent}# any tool here spends, moves or consumes something,"
                " the argument",
                f"{indent}# it carries that in has to be named by hand."]
    out = [f"{indent}# Arguments that look like the size of an effect, read"
           " from the",
           f"{indent}# schemas. Uncommented, these DEBIT a budget, and two"
           " tools sharing",
           f"{indent}# one limit must name the same budget or the limit is"
           " split in two."]
    choices = budgets or []
    if choices:
        out.append(f"{indent}# Pick the budget each one debits from"
                   f" {', '.join(choices)}.")
    for tool in valued:
        ident = (f", identity: {_flow(list(tool.identity_args))}"
                 if tool.identity_args else "")
        target = ", budget: WHICH" if choices else ""
        out.append(f"{indent}# {tool.name}: {{arg: {tool.amount_args[0]}"
                   f"{target}{ident}}}")
    return out
