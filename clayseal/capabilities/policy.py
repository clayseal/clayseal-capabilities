"""The policy document: authority as a file a person can read, diff and sign.

WHY THIS EXISTS

Everything this gateway enforces was, until now, constructed as Python objects at
the call site. `SessionBroker` has 48 fields and `DeployableStack.from_goal`
takes fourteen posture switches, one of which is a preserved negative result that
must never be enabled. `profiles.py` answered half of that by naming the posture.
This answers the other half by naming the AUTHORITY.

The distinction `profiles.py` draws is the one this module keeps:

    a PROFILE decides how the gateway behaves when the grant is silent.
    a POLICY is the grant.

A security team cannot review a constructor call. They can review a file, attach
it to a change ticket, diff it in a pull request, and sign it. The compiled
policy carries `digest()`, a hash over the canonical document, and the broker
puts it on every decision record, so an audit trail says which authority produced
each decision rather than only what the decision was.

WHAT IT DELIBERATELY DOES NOT DO

It does not write your intent envelope, and it does not replace the planner. The
envelope is derived from the sealed goal at seal time by a privileged planner
(see `docs/intent_envelope_generation.md`); a hand-written envelope in a YAML
file would be a plan the operator guessed at, and the guess would be wrong in the
direction of over-permission every time. The policy names the authority; the
planner names the plan.

FORMAT

    version: 1
    goal:
      id: ticket-triage
      summary: Triage open billing tickets and write a summary to out/summary.md
    profile: supervised            # autonomous | supervised | benchmark
    expires_at: 2026-08-24T00:00:00Z
    tools:
      allow: [list_tickets, read_ticket, write_summary, send_email]
      patterns: ["get_*"]                     # grant a FAMILY, unioned with allow
      harmless: [list_tickets, read_ticket]   # asserted to have no countable effect
      effects:                                # what each tool actually does
        write_summary: write
        send_email: send
    paths:
      allow: ["out/**", "tickets/**"]
      deny:  [".env", ".git/**"]
      arg_names: {write_summary: path}    # which argument carries the path
      pathless: [send_email]              # asserted to act on no path
    egress:
      domains: [acme-internal.com]
      recipients: [ops@acme-internal.com]
      bind_recipients: true
    budgets:
      value:
        ceilings: {refunds: "5000.00"}
        windows:  {refunds: 86400}        # rolling 24h, not per session
        tracked:
          issue_refund: {arg: amount, budget: refunds}
      calls:
        ceilings: {emails: 3}
        tracked:
          send_email: emails

Every section is optional except `goal`. An absent section means the gateway has
no authority to check there, which `lint()` reports rather than assumes is
intentional.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from clayseal.capabilities.call_budget import CallBudgetConfig, SessionCallBudget
from clayseal.capabilities.hardening.egress_policy import EgressPolicy
from clayseal.capabilities.scoping.goal import GoalSpec
from clayseal.capabilities.value_budget import SessionValueBudget, ValueBudgetConfig
from clayseal.core.hash_util import sha256_hex
from clayseal.core.task_scope import TaskScope, close_deny_patterns

#: Document versions this module knows how to compile. A policy without a
#: version, or with one from the future, is refused rather than interpreted
#: optimistically: an authority document read under the wrong schema grants
#: whatever the reader happened to understand.
SUPPORTED_VERSIONS = frozenset({1})

_PROFILES = {"autonomous", "supervised", "benchmark"}


class PolicyError(ValueError):
    """The document cannot be compiled. Never raised for a lint warning."""


@dataclass(frozen=True)
class Finding:
    """One lint result. `level` is 'error' or 'warning'."""

    level: str
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.level.upper():7} {self.code:24} {self.message}"


@dataclass(frozen=True)
class Policy:
    """A compiled policy document.

    `raw` is kept verbatim so `digest()` hashes what the author actually wrote,
    not a re-serialisation of what this module understood. Those differ exactly
    when a key was ignored, which is the case a digest most needs to catch.
    """

    raw: dict[str, Any]
    goal: GoalSpec
    profile: str
    scope: TaskScope | None = None
    egress: EgressPolicy | None = None
    value_budget: SessionValueBudget | None = None
    call_budget: SessionCallBudget | None = None
    allowed_tools: set[str] | None = None
    #: `tools.patterns`: an opt-in glob surface over tool names, UNIONed with
    #: `allowed_tools`. `SessionBroker.tool_patterns` has enforced this since
    #: the pattern work landed and only the benchmark harness could set it, so
    #: the held-out friction result in `generalisation.md` was measured against
    #: a mechanism no policy document could reach. This is the reach.
    tool_patterns: list[str] | None = None
    #: Compiled `tools.when`: conditional withdrawals from `allowed_tools`.
    conditional_tools: Any = None
    #: Tools the author asserts have no side effect worth counting. The mandate
    #: linter cannot tell a read from a write by name, so this is where a person
    #: says so, in the reviewed document rather than in a constructor call.
    harmless_tools: frozenset[str] = field(default_factory=frozenset)
    #: tool -> verb, declared by the author. The name-based classifier is a
    #: fallback tuned on benchmark catalogs, and real MCP servers do not name
    #: tools that way: of 24 names taken from widely used servers, 17 fall
    #: through to `call`, including `terraform_destroy` and `grant_role`. The
    #: floor's write and egress rules key off the verb, so an operator whose
    #: catalog does not read like a verb list needs somewhere to say what each
    #: tool does. This is that place.
    tool_verbs: dict[str, str] = field(default_factory=dict)
    #: tool -> the argument that carries the path it acts on. The floor looks for
    #: `file_path`, `path`, `filename` or `file`, and a tool that calls it
    #: anything else produces no path at all, so the path scope is skipped and
    #: the action is allowed. That is a control that stops applying when its
    #: input is unusual and reports success, which is the exact failure this
    #: repository names elsewhere. Declaring the argument restores the check.
    path_args: dict[str, str] = field(default_factory=dict)
    #: Tools the operator asserts act on no path at all. Without this there is no
    #: way to tell "this tool has no path" from "nobody told us its name", and
    #: the second one has to be treated as unverified.
    pathless_tools: frozenset[str] = field(default_factory=frozenset)
    source: str | None = None
    unknown_keys: tuple[str, ...] = field(default_factory=tuple)

    def digest(self) -> str:
        """Stable hash over the document, for the audit trail.

        `sort_keys` makes the hash independent of key order, so reformatting the
        YAML does not read as a change of authority, while any change of VALUE
        does. `default=str` is there because YAML parses a bare timestamp into a
        `datetime`, and the digest has to survive that rather than raise on it.
        """
        return "sha256:" + sha256_hex(
            json.dumps(
                self.raw, sort_keys=True, separators=(",", ":"), default=str
            ).encode()
        )

    # ------------------------------------------------------------------ #
    # Building the gateway
    # ------------------------------------------------------------------ #
    def build(self, **overrides: Any):
        """Build the `DeployableStack` this policy authorizes.

        `overrides` reach `DeployableStack.from_goal` and carry the things a
        document cannot hold: the intent envelope from the planner, a detector,
        a receipt sink, a clock. A posture switch passed here is refused by
        `Profile.build`, which is the behaviour we want: the profile named in the
        document is the posture, and a call site quietly changing it is the
        failure this whole module exists to make visible.
        """
        from clayseal.capabilities.profiles import AUTONOMOUS, BENCHMARK, SUPERVISED

        profile = {"autonomous": AUTONOMOUS, "supervised": SUPERVISED,
                   "benchmark": BENCHMARK}[self.profile]
        kwargs: dict[str, Any] = {
            "scope": self.scope,
            "egress": self.egress,
            "value_budget": self.value_budget,
            "call_budget": self.call_budget,
            "allowed_tools": self.allowed_tools,
            "tool_patterns": self.tool_patterns,
            "conditional_tools": self.conditional_tools,
            "declared_harmless": set(self.harmless_tools) or None,
        }
        kwargs = {k: v for k, v in kwargs.items() if v is not None}
        kwargs.update(overrides)
        stack = profile.build(self.goal, **kwargs)
        # The authority's identity travels with every decision it produced.
        object.__setattr__(stack, "policy_digest", self.digest())
        return stack

    # ------------------------------------------------------------------ #
    # Review
    # ------------------------------------------------------------------ #
    @property
    def principal(self) -> str:
        """The principal a ceiling is counted against, when one is declared."""
        raw = self.raw.get("deployment")
        return str(raw.get("principal", "")) if isinstance(raw, dict) else ""

    @property
    def stateless(self) -> bool:
        """Does this policy say it runs where no session survives a request?

        MCP 2026-07-28 removes the `initialize` handshake and the
        `Mcp-Session-Id` header, so a Streamable HTTP deployment behind a load
        balancer has no session for a ceiling to be scoped to. Declaring it here
        is what lets `lint` refuse a configuration that cannot work rather than
        warn about one that might be intentional.
        """
        raw = self.raw.get("deployment")
        return bool(raw.get("stateless")) if isinstance(raw, dict) else False

    def lint(self) -> list[Finding]:
        """Everything a reviewer should be asked about before this is deployed.

        Ordered errors first. An error means the document authorizes something it
        almost certainly did not mean to; a warning means a control is absent and
        the absence might be deliberate. Nothing here blocks `build`, because a
        linter that refuses is a linter people stop running.
        """
        out: list[Finding] = []
        raw = self.raw

        if self.unknown_keys:
            out.append(Finding(
                "warning", "unknown-keys",
                f"ignored by this version: {', '.join(self.unknown_keys)}. "
                f"A key that is silently dropped is authority the author thinks "
                f"they granted.",
            ))

        if not (self.goal.summary or "").strip():
            out.append(Finding(
                "error", "goal-summary-empty",
                "goal.summary is what the plan, the provenance roots and the "
                "content checks are all derived from. An empty one disables them.",
            ))

        expires = raw.get("expires_at")
        if not expires:
            out.append(Finding(
                "warning", "no-expiry",
                "no expires_at: this grant authorizes forever.",
            ))
        elif self.scope is not None and self.scope.is_expired():
            out.append(Finding(
                "error", "expired",
                f"expires_at {expires} is in the past; every action is denied.",
            ))

        if self.egress is None:
            out.append(Finding(
                "warning", "no-egress-policy",
                "no egress section: destinations are unchecked. This is the "
                "control that stops a read of in-scope data from leaving.",
            ))
        elif self.egress.allow_all:
            out.append(Finding(
                "error", "egress-allow-all",
                "egress.allow_all disables destination checking entirely.",
            ))
        else:
            broad = sorted(
                d for d in self.egress.allowed_domains
                if d.lower().lstrip(".") in _PUBLIC_SUFFIXES
            )
            if broad:
                out.append(Finding(
                    "error", "egress-public-suffix",
                    f"egress.domains lists {', '.join(broad)}, which is a public "
                    f"suffix rather than an organisation. A domain matches itself "
                    f"AND everything under it, so this allows most of the "
                    f"internet while looking like an allow-list.",
                ))
        if self.egress is not None and not self.egress.allow_all and (
                not self.egress.allowed_domains and not self.egress.allowed_recipients):
            out.append(Finding(
                "warning", "egress-empty",
                "egress section present but empty, so every destination is "
                "denied. If that is intended, say so with domains: [].",
            ))

        if self.scope is None:
            out.append(Finding(
                "warning", "no-path-scope",
                "no paths section: file actions are bounded only by the "
                "protected-zone list, not by this grant.",
            ))
        elif self.scope.allowed_paths and any(
            p.strip() in {"/", "**", "/**", "*"} for p in self.scope.allowed_paths
        ):
            out.append(Finding(
                "error", "path-scope-universal",
                "paths.allow contains a universal pattern, which grants the "
                "whole filesystem and makes the rest of the section decorative.",
            ))

        if self.allowed_tools is None and self.tool_patterns is None:
            out.append(Finding(
                "warning", "no-tool-allowlist",
                "no tools.allow: any tool the agent can reach is in scope.",
            ))

        if self.tool_patterns:
            # A pattern grant is the one part of this document whose extent is
            # not visible from reading it: `get_*` is a sentence, and what it
            # admits depends on a catalog the document does not contain. Say so
            # every time, with the patterns spelled out, so the reviewer knows
            # this is the line to check against the server's `tools/list`.
            out.append(Finding(
                "warning", "tool-pattern-grant",
                f"tools.patterns grants by shape, not by name: "
                f"{', '.join(self.tool_patterns)}. What this admits depends on "
                f"the server's catalog, so check it against `tools/list` rather "
                f"than against this file. `clayseal policy init` prints the "
                f"catalog a server actually advertises.",
            ))
            broad = sorted(p for p in self.tool_patterns if p.startswith("*"))
            if broad:
                out.append(Finding(
                    "warning", "tool-pattern-leading-wildcard",
                    f"{', '.join(broad)} begins with a wildcard, so it matches on "
                    f"suffix alone: `*_data` admits `delete_data` as readily as "
                    f"`read_data`. A prefix pattern names a family; a suffix "
                    f"pattern names whatever happens to end that way.",
                ))

        undeclared = self.tools_with_unverifiable_paths()
        if undeclared:
            out.append(Finding(
                "warning", "path-arg-not-declared",
                f"a path scope is set and {', '.join(undeclared)} do not say "
                f"which argument carries their path. If they use one of "
                f"{', '.join(DEFAULT_PATH_ARGS)} this is fine and nothing "
                f"happens. If they use anything else the scope cannot be applied, "
                f"and the proxy refuses the call rather than allowing an "
                f"unverified write. Map the argument under paths.arg_names, or "
                f"list the tool under paths.pathless if it acts on no path. "
                f"A warning rather than an error because a document cannot tell "
                f"which case a tool is in; the runtime can, and does.",
            ))

        unclassified = self.unclassified_tools()
        if unclassified:
            out.append(Finding(
                "warning", "verb-not-declared",
                f"the verb of {', '.join(unclassified)} was guessed from the "
                f"name and came back as 'call', meaning unrecognised. The floor's "
                f"write and egress rules key off the verb. Declare them under "
                f"tools.effects.",
            ))

        # The effect-coverage question is not asked here with a keyword
        # heuristic. `mandate_lint` already answers it properly, by tool family
        # and by reachability, and the AUTONOMOUS and SUPERVISED profiles refuse
        # to build on an error from it. Running the same linter here means
        # `policy lint` reports what `policy build` would refuse, instead of the
        # author finding out from a traceback.
        out.extend(self.mandate_findings())

        return sorted(out, key=lambda f: (f.level != "error", f.code))

    def verb_for(self, tool: str) -> str:
        """The verb this policy assigns to `tool`, declared or inferred."""
        from clayseal.capabilities.tool_verbs import classify_verb

        return self.tool_verbs.get(tool) or classify_verb(tool)

    def unclassified_tools(self) -> list[str]:
        """Allowed tools whose verb nobody declared and the classifier guessed.

        `call` is the classifier saying it does not recognise the name. It is the
        conservative answer rather than a wrong one, but it is not the verb, and
        the floor's write and egress rules key off the verb.
        """
        from clayseal.capabilities.tool_verbs import classify_verb

        return sorted(
            t for t in (self.allowed_tools or ())
            if t not in self.tool_verbs and classify_verb(t) == "call"
        )

    def tools_with_unverifiable_paths(self) -> list[str]:
        """Effectful tools that have not said where their path is.

        Some of them are fine: a tool whose argument is called `path` needs no
        declaration. A document cannot tell which, so this is reported as a
        question rather than a verdict, and the runtime check in `mcp_proxy`,
        which sees the actual arguments, is the control.

        Only meaningful when a path scope exists. It cannot be answered from
        names alone in general, so it is answered from what the operator
        declared: a tool is verifiable if its path argument is mapped, or it is
        asserted to have none. Anything else is a tool whose writes will be
        allowed without the scope ever being consulted.
        """
        if self.scope is None or not (
            self.scope.allowed_paths or self.scope.denied_paths
        ):
            return []
        return sorted(
            t for t in (self.allowed_tools or ())
            if self.verb_for(t) not in ("read", "call")
            and t not in self.path_args
            and t not in self.pathless_tools
        )

    def path_arg_for(self, tool: str) -> str | None:
        """The argument this policy says carries `tool`'s path, if declared."""
        return self.path_args.get(tool)

    def mandate_findings(self) -> list[Finding]:
        """Effects this document leaves uncounted, from the shared linter."""
        from clayseal.capabilities.mandate_lint import lint_mandate

        def cfg(budget, attr):
            return dict(getattr(getattr(budget, "config", None), attr, {}) or {})

        try:
            raw = lint_mandate(
                catalog=sorted(self.allowed_tools or ()),
                declared_harmless=sorted(self.harmless_tools),
                value_tracked=cfg(self.value_budget, "tracked"),
                call_tracked=cfg(self.call_budget, "tracked"),
                ceilings={**cfg(self.value_budget, "ceilings"),
                          **cfg(self.call_budget, "ceilings")},
                principal_scoped=bool(self.principal),
                stateless=self.stateless,
            )
        except Exception as exc:  # noqa: BLE001 - a linter must not be the thing that breaks
            return [Finding("warning", "mandate-lint-unavailable", str(exc))]
        return [
            Finding(f.severity, f.code, f"{f.subject}: {f.detail}") for f in raw
        ]

    def describe(self) -> str:
        """The compiled authority as text, for a startup log or a review."""
        lines = [
            f"policy:  {self.source or '<inline>'}",
            f"digest:  {self.digest()}",
            f"goal:    {self.goal.query_id}  {self.goal.summary!r}",
            f"profile: {self.profile}",
        ]
        tools = sorted(self.allowed_tools) if self.allowed_tools else None
        lines.append(f"tools:   {', '.join(tools) if tools else '(any)'}")
        if self.tool_patterns:
            lines.append(f"patterns: {', '.join(self.tool_patterns)}  "
                         f"(matched against the server's catalog at runtime)")
        if self.harmless_tools:
            lines.append(f"harmless: {', '.join(sorted(self.harmless_tools))}")
        if self.allowed_tools:
            lines.append("effects: " + ", ".join(
                f"{t}={self.verb_for(t)}" for t in sorted(self.allowed_tools)))
        if self.scope is not None:
            lines.append(f"paths:   allow={self.scope.allowed_paths} "
                         f"deny={self.scope.denied_paths}")
            lines.append(f"expires: {self.scope.expires_at or '(never)'}")
        else:
            lines.append("paths:   (unscoped)")
        if self.egress is not None:
            lines.append(f"egress:  domains={sorted(self.egress.allowed_domains)} "
                         f"recipients={sorted(self.egress.allowed_recipients)}")
        else:
            lines.append("egress:  (unchecked)")
        if self.value_budget is not None:
            lines.append(f"value:   {dict(self.value_budget.config.ceilings)}")
        if self.call_budget is not None:
            lines.append(f"calls:   {dict(self.call_budget.config.ceilings)}")
        return "\n".join(lines)


# ---------------------------------------------------------------------- #
# Loading
# ---------------------------------------------------------------------- #
_TOP_LEVEL = {
    "version", "goal", "profile", "expires_at", "tools", "paths", "egress",
    "budgets", "resources", "deployment",
}


def load_policy(path: str | Path) -> Policy:
    """Compile a policy document from a YAML or JSON file."""
    p = Path(path)
    try:
        text = p.read_text()
    except OSError as exc:
        raise PolicyError(f"cannot read policy {p}: {exc}") from exc
    return load_policy_text(text, source=str(p))


def load_policy_text(text: str, *, source: str = "<policy>") -> Policy:
    """Compile a policy document held as text.

    A deployment that keeps its grants in a config service, a database or a
    request body has the document in memory and no file, and writing one out to
    a temporary path to read it back is not a step anything should have to
    take. `source` is what error messages name, so make it the place the text
    actually came from.
    """
    import yaml

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"{source} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError(f"{source} must contain a mapping at the top level")
    return compile_policy(raw, source=source)


def compile_policy(raw: dict[str, Any], *, source: str | None = None) -> Policy:
    """Compile an already-parsed document.

    Refuses rather than guesses. Every rejection here is a case where continuing
    would produce a gateway that enforces something other than what the document
    says, and a gateway that enforces the wrong thing is worse than one that will
    not start.
    """
    version = raw.get("version")
    if version is None:
        raise PolicyError(
            "policy has no `version`. Add `version: 1`, so a document written "
            "for a later schema is refused instead of half-understood."
        )
    if version not in SUPPORTED_VERSIONS:
        raise PolicyError(
            f"policy version {version!r} is not supported by this build "
            f"(known: {sorted(SUPPORTED_VERSIONS)})"
        )

    goal_raw = raw.get("goal")
    if not isinstance(goal_raw, dict):
        raise PolicyError("policy needs a `goal` mapping with `id` and `summary`")
    goal_id = str(goal_raw.get("id") or goal_raw.get("query_id") or "").strip()
    if not goal_id:
        raise PolicyError("goal.id is required and identifies the session")
    goal = GoalSpec(
        query_id=goal_id,
        summary=str(goal_raw.get("summary") or "").strip(),
        allow_resources=[str(r) for r in (raw.get("resources") or [])],
    )

    profile = str(raw.get("profile") or "supervised").strip().lower()
    if profile not in _PROFILES:
        raise PolicyError(
            f"unknown profile {profile!r}; one of {sorted(_PROFILES)}. The "
            f"profile decides what happens to an action the floor cleared and "
            f"the plan did not predict, so there is no safe default to fall back "
            f"on when the name is wrong."
        )

    expires_at = _iso_or_none(raw.get("expires_at"))

    tools_raw = raw.get("tools")
    allowed_tools: set[str] | None = None
    tool_patterns: list[str] | None = None
    harmless: frozenset[str] = frozenset()
    tool_verbs: dict[str, str] = {}
    if isinstance(tools_raw, dict):
        if tools_raw.get("allow") is not None:
            allowed_tools = {str(t) for t in _as_list(tools_raw["allow"], "tools.allow")}
        if tools_raw.get("patterns") is not None:
            tool_patterns = _tool_patterns_from(tools_raw["patterns"])
        harmless = frozenset(
            str(t) for t in _as_list(tools_raw.get("harmless"), "tools.harmless")
        )
        stray = sorted(harmless - (allowed_tools or harmless))
        if stray:
            raise PolicyError(
                f"tools.harmless names tools that are not in tools.allow: {stray}. "
                f"Declaring a tool harmless that the agent cannot reach hides a "
                f"typo as an assertion."
            )
        tool_verbs = _verbs_from(tools_raw.get("effects"), allowed_tools,
                                 patterns=tool_patterns)
    elif isinstance(tools_raw, list):
        allowed_tools = {str(t) for t in tools_raw}

    path_args = _path_args_from(raw, allowed_tools, tool_patterns)
    pathless = _pathless_from(raw, allowed_tools, tool_patterns)
    scope = _scope_from(raw, goal, expires_at)
    egress = _egress_from(raw.get("egress"))
    value_budget, call_budget = _budgets_from(raw.get("budgets"))
    value_budget = _bind_principal(raw.get("deployment"), value_budget)

    unknown = tuple(sorted(k for k in raw if k not in _TOP_LEVEL))

    return Policy(
        raw=raw,
        goal=goal,
        profile=profile,
        scope=scope,
        egress=egress,
        value_budget=value_budget,
        call_budget=call_budget,
        allowed_tools=allowed_tools,
        tool_patterns=tool_patterns,
        conditional_tools=_tool_guards_from(tools_raw, allowed_tools),
        harmless_tools=harmless,
        tool_verbs=tool_verbs,
        path_args=path_args,
        pathless_tools=pathless,
        source=source,
        unknown_keys=unknown,
    )


#: The verbs the floor understands. `read` is the only one it treats as
#: reversible, so getting this wrong in that direction is the expensive mistake
#: and the compiler will not accept a value outside this set.
KNOWN_VERBS = frozenset({"read", "write", "send", "transfer", "call"})

#: Suffixes that are not an organisation. `domains` matches a name and every name
#: under it, so listing one of these allows most of the internet. Not exhaustive,
#: and it does not need to be: it catches the mistake people actually make.
_PUBLIC_SUFFIXES = frozenset({
    "com", "net", "org", "io", "co", "dev", "app", "ai", "cloud", "xyz",
    "co.uk", "com.au", "co.jp", "com.br", "amazonaws.com", "googleapis.com",
    "windows.net", "azurewebsites.net", "herokuapp.com", "vercel.app",
    "github.io", "pages.dev", "workers.dev", "ngrok.io", "ngrok-free.app",
})


def _verbs_from(raw: Any, allowed_tools: set[str] | None, *,
                patterns: list[str] | None = None) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise PolicyError(
            "tools.effects must be a mapping of tool name to verb, one of "
            f"{sorted(KNOWN_VERBS)}"
        )
    out: dict[str, str] = {}
    for tool, verb in raw.items():
        verb = str(verb).strip().lower()
        if verb not in KNOWN_VERBS:
            raise PolicyError(
                f"tools.effects.{tool} is {verb!r}; expected one of "
                f"{sorted(KNOWN_VERBS)}"
            )
        out[str(tool)] = verb
    stray = _uncovered(out, allowed_tools, patterns)
    if stray:
        raise PolicyError(
            f"tools.effects names tools that are not in tools.allow "
            f"or matched by tools.patterns: {stray}"
        )
    return out


#: A pattern this broad grants the whole catalog and makes the section
#: decorative, the same failure `path-scope-universal` exists to stop one
#: dimension over. Refused at compile time rather than warned about, because a
#: grant nobody can read is not reviewable and this is the field whose entire
#: purpose is to be read in a pull request.
_UNIVERSAL_TOOL_PATTERNS = {"*", "**", "?*", "*?"}


def _tool_patterns_from(value: Any) -> list[str]:
    """Parse `tools.patterns`, an OPT-IN glob surface over tool names.

    ## Why this exists, and why it is a separate field

    `SessionBroker.tool_patterns` has been enforced since the pattern work
    landed (`broker.py`, fnmatch against the granted set) and was reachable only
    from the benchmark harness: `benchmarks/core/patterns.py` built it,
    `stack_factory` passed it, and no policy document could say it. So the
    largest friction result in the project, held-out false blocks falling from
    47.91% to 0.05% on tau2 once a grant is written as patterns rather than as
    the instance list a logger produces, was measured against a mechanism a user
    could not deploy. See `benchmarks/results/generalisation.md`.

    It is `tools.patterns` and not a glob inside `tools.allow` for two reasons.
    A name in `allow` stays a literal, so no existing document changes meaning,
    and a tool genuinely called `get_*` is still grantable. And a reviewer
    reading a diff sees the field whose contents need scrutiny, rather than
    having to notice a metacharacter inside a list of names.

    Patterns UNION with `allow`; they widen, never narrow. That is the correct
    semantics for a grant and it is exactly why the universal forms are refused
    here and why `policy lint` reports what a pattern admits against a catalog
    when it knows one.
    """
    patterns = [str(p).strip() for p in _as_list(value, "tools.patterns")]
    empty = [p for p in patterns if not p]
    if empty:
        raise PolicyError("tools.patterns contains an empty pattern")
    universal = sorted(p for p in patterns if p in _UNIVERSAL_TOOL_PATTERNS)
    if universal:
        raise PolicyError(
            f"tools.patterns contains a universal pattern {universal}, which "
            f"grants every tool the agent can reach and makes tools.allow "
            f"decorative. Name the surface, or drop the tools section and let "
            f"`no-tool-allowlist` say plainly that nothing is scoped."
        )
    literal = sorted(p for p in patterns if not any(c in p for c in "*?["))
    if literal:
        raise PolicyError(
            f"tools.patterns contains entries with no wildcard: {literal}. "
            f"A literal name belongs in tools.allow, where a reader can see it "
            f"is one tool and not a family."
        )
    return patterns


def _as_list(value: Any, where: str) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        raise PolicyError(f"{where} must be a list, not a single string")
    if not isinstance(value, list):
        raise PolicyError(f"{where} must be a list")
    return value


def _iso_or_none(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    text = str(value).strip()
    if not text:
        return None
    probe = text.replace("Z", "+00:00")
    try:
        datetime.fromisoformat(probe)
    except ValueError as exc:
        raise PolicyError(
            f"expires_at {text!r} is not ISO 8601. An expiry that cannot be "
            f"parsed counts as expired, so a typo here would deny everything."
        ) from exc
    return text


#: Argument names the floor already recognises without a declaration.
DEFAULT_PATH_ARGS = ("file_path", "path", "filename", "file")


def _paths_section(raw: dict) -> dict[str, Any]:
    paths = raw.get("paths")
    return paths if isinstance(paths, dict) else {}


def _uncovered(names, allowed_tools: set[str] | None,
               patterns: list[str] | None) -> list[str]:
    """Which of `names` the grant does not cover, by literal OR by pattern.

    Three sections cross-check themselves against the tool grant: `effects`,
    `paths.arg_names` and `paths.pathless`. Each did its own `set - (allow or
    set)` and so each had to learn about patterns separately, and each would
    have been a separate way for the feature to be unusable: declaring what a
    pattern-granted tool DOES, or which argument carries its path, raised
    "names tools that are not in tools.allow".

    The `or names` fallback is the "no allowlist means no constraint" rule and
    it has to be conditioned on BOTH dimensions being absent. Written as
    `allowed_tools or names` it silently covered everything whenever only
    patterns were declared, which is precisely the document this field exists
    for.
    """
    names = set(names)
    if allowed_tools is None and not patterns:
        return []
    covered = set(allowed_tools or ())
    if patterns:
        import fnmatch

        covered |= {n for n in names
                    if any(fnmatch.fnmatch(n, p) for p in patterns)}
    return sorted(names - covered)


def _path_args_from(raw: dict, allowed_tools: set[str] | None,
                    patterns: list[str] | None = None) -> dict[str, str]:
    section = _paths_section(raw).get("arg_names")
    if section is None:
        return {}
    if not isinstance(section, dict):
        raise PolicyError(
            "paths.arg_names must be a mapping of tool name to the argument that "
            "carries its path, for example {tf_apply: target_dir}"
        )
    out = {str(t): str(a) for t, a in section.items()}
    stray = _uncovered(out, allowed_tools, patterns)
    if stray:
        raise PolicyError(
            f"paths.arg_names names tools that are not in tools.allow: {stray}"
        )
    return out


def _pathless_from(raw: dict, allowed_tools: set[str] | None,
                   patterns: list[str] | None = None) -> frozenset[str]:
    listed = _as_list(_paths_section(raw).get("pathless"), "paths.pathless")
    out = frozenset(str(t) for t in listed)
    stray = _uncovered(out, allowed_tools, patterns)
    if stray:
        raise PolicyError(
            f"paths.pathless names tools that are not in tools.allow: {stray}"
        )
    return out


def _scope_from(raw: dict, goal: GoalSpec, expires_at: str | None) -> TaskScope | None:
    paths = raw.get("paths")
    if paths is None and expires_at is None:
        return None
    allow: list[str] = []
    deny: list[str] = []
    if isinstance(paths, dict):
        allow = [str(p) for p in _as_list(paths.get("allow"), "paths.allow")]
        deny = [str(p) for p in _as_list(paths.get("deny"), "paths.deny")]
    elif isinstance(paths, list):
        allow = [str(p) for p in paths]
    elif paths is not None:
        raise PolicyError("paths must be a mapping with allow/deny, or a list")
    return TaskScope(
        allowed_paths=allow,
        denied_paths=_close_deny_patterns(deny),
        allowed_resources=list(goal.allow_resources),
        task_summary=goal.summary or None,
        mandate_id=goal.query_id,
        source_schema="clayseal.policy/v1",
        expires_at=expires_at,
    )


def _close_deny_patterns(deny: list[str]) -> list[str]:
    """One implementation, in `core.task_scope`, applied on every path to a scope.

    This wrapper stays because the name is referenced in the policy docs and the
    tests; the behaviour lives with `TaskScope`, which now closes its own deny
    list in `__post_init__` so a directly-constructed scope is closed too.
    """
    return close_deny_patterns(deny)


def _bind_principal(deployment: Any, value_budget: Any) -> Any:
    """Move the value ceiling off the session and onto the principal.

    MCP 2026-07-28 removes the `initialize` handshake and the session id header
    so any instance can serve any request. A ceiling counted per session then
    counts over nothing: it resets every call and the aggregate rung is inert.
    `PrincipalBudgetView` is the anchor that outlives a request, and this is the
    line of policy that reaches it.

    Nothing changes for a document that declares no principal, so every existing
    policy compiles to exactly the object it did.
    """
    if not isinstance(deployment, dict) or value_budget is None:
        return value_budget
    principal = str(deployment.get("principal", "")).strip()
    if not principal:
        return value_budget

    from clayseal.capabilities.principal_ledger import (
        PrincipalBudgetView,
        PrincipalLedger,
    )

    ledger_raw = deployment.get("ledger")
    if ledger_raw is not None and not isinstance(ledger_raw, dict):
        raise PolicyError("deployment.ledger must be a mapping")
    ledger_raw = ledger_raw or {}
    path = ledger_raw.get("path")
    window = ledger_raw.get("window_seconds")
    kwargs: dict[str, Any] = {}
    if path is not None:
        from pathlib import Path as _Path
        kwargs["path"] = _Path(str(path))
    if window is not None:
        try:
            kwargs["window_seconds"] = int(window)
        except (TypeError, ValueError) as exc:
            raise PolicyError(
                "deployment.ledger.window_seconds must be a whole number of "
                "seconds") from exc
    if not path and bool(deployment.get("stateless")):
        # An in-memory ledger in a stateless deployment is a session ledger
        # wearing a different name: it dies with the process, and a stateless
        # deployment is many processes. Refusing is the same discipline as the
        # rest of this compiler.
        raise PolicyError(
            "deployment declares stateless and a principal but no "
            "deployment.ledger.path. An in-memory principal ledger dies with "
            "the process, and a stateless deployment is many processes, so the "
            "ceiling would still reset. Give the ledger durable storage.")

    view = PrincipalBudgetView(ledger=PrincipalLedger(**kwargs),
                               principal=principal)
    view.config = value_budget.config
    return view


def _tool_guards_from(tools_raw: Any, allowed: Any) -> Any:
    """Compile `tools.when` into a conditional withdrawal, or None.

    Measured on four `tau2-bench` policy documents, 31% of the sentences that
    state a rule are state-conditional prohibitions: "an order can only be
    cancelled if its status is pending". A guarded CEILING expresses none of
    them, because none is about an amount. Returning None when the section is
    absent keeps every existing document compiling to exactly what it did.
    """
    if not isinstance(tools_raw, dict) or tools_raw.get("when") is None:
        return None
    if not allowed:
        raise PolicyError(
            "tools.when withdraws from tools.allow, and this document grants "
            "no tools to withdraw from. A conditional rule over an unbounded "
            "catalogue would read as enforcement and do nothing.")
    from clayseal.capabilities.conditional_ceiling import tool_guards_from_config

    try:
        return tool_guards_from_config(tools_raw["when"], allowed)
    except ValueError as exc:
        raise PolicyError(str(exc)) from exc


def _egress_from(raw: Any) -> EgressPolicy | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise PolicyError("egress must be a mapping")
    allow_all = bool(raw.get("allow_all", False))
    return EgressPolicy(
        allowed_domains={str(d).lower() for d in _as_list(raw.get("domains"), "egress.domains")},
        allowed_recipients={
            str(r).lower() for r in _as_list(raw.get("recipients"), "egress.recipients")
        },
        self_identifiers={
            str(s).lower() for s in _as_list(raw.get("self"), "egress.self")
        },
        bind_recipients=bool(raw.get("bind_recipients", False)),
        allow_all=allow_all,
    )


def _budgets_from(raw: Any) -> tuple[SessionValueBudget | None, SessionCallBudget | None]:
    if raw is None:
        return None, None
    if not isinstance(raw, dict):
        raise PolicyError("budgets must be a mapping with `value` and/or `calls`")

    value_budget = None
    v = raw.get("value")
    if v is not None:
        if not isinstance(v, dict):
            raise PolicyError("budgets.value must be a mapping")
        # A rolling window turns "no more than $X ever" into "no more than $X per
        # window", which is the shape most business rules are written as. Absent,
        # the budget is session-cumulative exactly as before.
        windows: dict[str, float] = {}
        for budget_id, seconds in (v.get("windows") or {}).items():
            if not isinstance(seconds, (int, float)) or seconds <= 0:
                raise PolicyError(
                    f"budgets.value.windows.{budget_id} must be a positive "
                    f"number of seconds; a window of zero or less evicts "
                    f"everything immediately and keeps looking like a ceiling"
                )
            windows[str(budget_id)] = float(seconds)
        tracked: dict[str, tuple[str, str]] = {}
        for tool, spec in (v.get("tracked") or {}).items():
            if not isinstance(spec, dict) or "arg" not in spec or "budget" not in spec:
                raise PolicyError(
                    f"budgets.value.tracked.{tool} needs `arg` (which argument "
                    f"carries the amount) and `budget` (which ceiling it debits)"
                )
            identity = spec.get("identity")
            if identity is None:
                tracked[str(tool)] = (str(spec["arg"]), str(spec["budget"]))
                continue
            # `identity` turns a ceiling into "once per object, under ceiling".
            # A ceiling answers "is the total under the limit" correctly while the
            # same invoice is paid twice, and both halves are real constraints.
            if isinstance(identity, str) or not isinstance(identity, list):
                raise PolicyError(
                    f"budgets.value.tracked.{tool}.identity must be a list of "
                    f"argument names, for example [employee, period]"
                )
            from clayseal.capabilities.value_budget import EffectSpec

            tracked[str(tool)] = EffectSpec(
                budget_id=str(spec["budget"]), amount_arg=str(spec["arg"]),
                identity_args=tuple(str(a) for a in identity))
        ceilings = {str(k): val for k, val in (v.get("ceilings") or {}).items()}
        _check_ceilings_cover(tracked, ceilings, "value", _budget_id_of)
        guards = _guards_from(v.get("when"), ceilings)
        stray = sorted(set(windows) - set(ceilings))
        if stray:
            raise PolicyError(
                f"budgets.value.windows names budget ids with no ceiling: "
                f"{stray}. A window on nothing is not a control."
            )
        if guards:
            from clayseal.capabilities.conditional_ceiling import GuardedCeilings

            try:
                config = GuardedCeilings(tracked=tracked, ceilings=ceilings,
                                         guards=guards)
            except ValueError as exc:
                # The guard machinery refuses a raising guard, and that refusal is
                # a policy error rather than a crash: the document asked for
                # something the design does not permit.
                raise PolicyError(str(exc)) from exc
        else:
            config = ValueBudgetConfig(tracked=tracked, ceilings=ceilings)
        if windows:
            from clayseal.capabilities.windowed_budget import WindowedValueBudget

            value_budget = WindowedValueBudget(config=config, windows=windows)
        else:
            value_budget = SessionValueBudget(config=config)

    call_budget = None
    c = raw.get("calls")
    if c is not None:
        if not isinstance(c, dict):
            raise PolicyError("budgets.calls must be a mapping")
        tracked_c = {str(k): str(val) for k, val in (c.get("tracked") or {}).items()}
        ceilings_c: dict[str, int] = {}
        for k, val in (c.get("ceilings") or {}).items():
            try:
                ceilings_c[str(k)] = int(val)
            except (TypeError, ValueError) as exc:
                raise PolicyError(
                    f"budgets.calls.ceilings.{k} must be a whole number of calls"
                ) from exc
        _check_ceilings_cover(tracked_c, ceilings_c, "calls", lambda t: t)
        call_budget = SessionCallBudget(
            config=CallBudgetConfig(tracked=tracked_c, ceilings=ceilings_c)
        )

    return value_budget, call_budget


def _guards_from(raw: Any, ceilings: dict[str, Any]) -> tuple:
    """Conditional tightenings, from `budgets.value.when`.

    A guard may only lower a ceiling. The document cannot express the opposite
    and the compiler says why rather than silently dropping it: a condition
    arrives as tool output, so a guard that could raise a ceiling would let
    injected content widen a grant. Raising authority is what step-up is for.
    """
    if raw is None:
        return ()
    from clayseal.capabilities.conditional_ceiling import Guard

    if not isinstance(raw, list):
        raise PolicyError(
            "budgets.value.when must be a list of {if: {...}, ceilings: {...}}"
        )
    guards = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise PolicyError(f"budgets.value.when[{i}] must be a mapping")
        condition = entry.get("if")
        limits = entry.get("ceilings")
        if not isinstance(condition, dict) or not condition:
            raise PolicyError(
                f"budgets.value.when[{i}] needs a non-empty `if` mapping of fact "
                f"name to required value; a guard with no condition is a base "
                f"ceiling written in the wrong place"
            )
        if not isinstance(limits, dict) or not limits:
            raise PolicyError(
                f"budgets.value.when[{i}] needs a `ceilings` mapping saying what "
                f"tightens when the condition holds"
            )
        unknown = sorted(set(limits) - set(ceilings))
        if unknown:
            raise PolicyError(
                f"budgets.value.when[{i}] tightens budget ids with no base "
                f"ceiling: {unknown}"
            )
        guards.append(Guard(when=dict(condition), ceilings=dict(limits),
                            reason=str(entry.get("reason") or "")))
    return tuple(guards)


def _budget_id_of(spec) -> str:
    """The budget id a tracked entry debits, whichever form it takes."""
    return getattr(spec, "budget_id", None) or (spec[1] if len(spec) > 1 else "")


def _check_ceilings_cover(tracked, ceilings, section, budget_of) -> None:
    """A tracked tool pointing at a ceiling nobody declared has no limit.

    Refused rather than warned about. The document reads as though the tool is
    bounded, the runtime finds no ceiling for that id, and the call proceeds: an
    author reading this file would conclude a control exists that does not.
    """
    missing = sorted(
        {budget_of(spec) for spec in tracked.values()} - set(ceilings)
    )
    if missing:
        raise PolicyError(
            f"budgets.{section}.tracked refers to budget ids with no ceiling: "
            f"{missing}. A tracked tool with no ceiling is unbounded, and the "
            f"document reads as though it is bounded."
        )
