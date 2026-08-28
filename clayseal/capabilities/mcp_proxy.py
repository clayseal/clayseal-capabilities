"""An MCP stdio proxy: the gateway, in front of the tools, not inside the agent.

WHAT THIS CHANGES

`SessionBroker.authorize` is a method the agent's harness chooses to call. That
is a real control when you own the harness and a fiction when you do not: a tool
the integration forgot to wrap, a second agent someone started next to the first,
or a harness whose loop was subverted all reach the tools without passing the
gate. The library cannot fix that, because the library is inside the thing it is
supposed to be checking.

A proxy can. It speaks MCP on both sides and sits between the agent and the
server:

    agent  <--stdio-->  clayseal proxy  <--stdio-->  mcp server

Every `tools/call` crosses this process. A denial is answered here and never
reaches the server, so the effect does not happen, whatever the agent intended.
The trust property is worth stating exactly: this mediates every call that goes
through this transport. An agent that can reach the tool by another route (its
own network access, a second server it started itself) is outside the boundary,
and closing THAT is what the syscall tier is for.

`tools/list` is filtered as well as `tools/call` checked. A tool outside the
policy is not advertised, so the agent does not plan around it and then get
refused. Denying at the last moment is correct and expensive; not offering is
correct and cheap, and both are needed because a client can call a tool it was
never told about.

SESSION LIFETIME, WHICH YOU HAVE TO DECIDE

One proxy process is one session. The goal comes from the policy document and
never changes, and every ceiling in that document is spent over the life of the
process. So a policy that allows three emails allows three emails **in total**,
not three per task, and an agent doing its fourth unrelated piece of work that
day is refused for spending the first three tasks' allowance.

That is the correct semantics for the constraint this layer exists to enforce, and
it is the wrong semantics if you meant "per task". Pick one deliberately:

- **One process per task.** Start the proxy with the task, stop it after. The
  ceilings mean what the document says and nothing carries over.
- **One long-lived process.** Ceilings are a rate limit on the whole connection.
  Size them for the connection, not for one task.
- **A long-lived process with task boundaries.** Call `new_session()` from your
  own control plane when a task ends.

`new_session()` is deliberately NOT wired to MCP's `initialize`, even though that
is where a client announces a new session. `initialize` arrives from the agent
side of the boundary, so resetting on it would let anything that can speak the
protocol clear its own budget by reconnecting, which is the exact attack budgets
exist to stop. A session boundary is a control-plane decision and has to come
from the control plane.

WHAT IT DOES NOT DO

It does not seal an intent envelope. The envelope comes from a privileged planner
that reads the goal before any untrusted content exists, and this process sees
its first message after the agent has already started. Pass one in with
`--envelope` when you have one; without it the floor, the budgets and the egress
policy still apply, which is the deployable envelope the benchmarks measure.

FRAMING, AND WHY WHAT LEAVES IS NOT WHAT ARRIVED

MCP's stdio transport is newline-delimited JSON-RPC. One message per line, no
Content-Length headers. Anything unparseable is forwarded untouched rather than
dropped: a proxy that silently eats a frame it did not understand turns a
protocol extension into a hang.

A message this proxy DOES understand is re-serialised from what it parsed rather
than forwarded byte for byte. That is deliberate and it closes a class of attack,
not a cosmetic choice. A proxy that authorises its own parse and forwards the
original bytes is only as correct as the agreement between two JSON parsers, and

    {"name": "wire_transfer", "name": "read_ticket"}

is a real disagreement: Python keeps the last duplicate key, and a parser that
keeps the first executes the transfer this proxy believed it had cleared.
Duplicate keys are refused outright and everything else is normalised, so the
server can only ever see the object that was authorised.

The same reasoning applies to the method name. Anything that is not exactly
`tools/call` but normalises to it, `"tools/call "` or `"Tools/Call"`, is refused
rather than forwarded, because forwarding it means betting that the server is
exactly as strict about the string as this proxy is.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TextIO

from clayseal.capabilities.monitor.action import Action
from clayseal.capabilities.tool_verbs import classify_verb


def _flatten_strings(value: Any, depth: int = 0) -> list[str]:
    """Strings inside a value, one level of nesting at a time, bounded."""
    if depth > 4:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for item in value:
            out.extend(_flatten_strings(item, depth + 1))
        return out
    if isinstance(value, dict):
        out = []
        for item in value.values():
            out.extend(_flatten_strings(item, depth + 1))
        return out
    return []


class MalformedMessage(ValueError):
    """The message cannot be authorised unambiguously, so it is not forwarded."""


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """`object_pairs_hook` that refuses a duplicated key instead of picking one.

    Picking one is what makes a parser differential exploitable. There is no
    correct choice to make here: the message means two things, and a gateway
    that has to guess which is not a gateway.
    """
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise MalformedMessage(
                f"duplicate JSON key {key!r}; the message has two meanings and "
                f"only one of them can be authorized"
            )
        seen[key] = value
    return seen


def _strict_loads(raw: str) -> Any:
    return json.loads(raw, object_pairs_hook=_no_duplicate_keys)


def _key(request_id: Any) -> Any:
    """JSON-RPC ids may be a string or a number, and `1` and `"1"` are distinct."""
    return (type(request_id).__name__, request_id)


def _outcome_name(decision: Any) -> str:
    """The decision's outcome as a plain string, whichever type it arrived as.

    `SessionBroker.authorize` returns a `BrokerDecision` whose `outcome` is an
    `Outcome` enum; `DeployableStack.authorize` returns a `StackDecision` whose
    `outcome` is already `outcome.value`. Both are supported gateways, so the
    proxy has to read both without caring which it was handed.
    """
    outcome = getattr(decision, "outcome", None)
    return str(getattr(outcome, "value", outcome) or "")

#: The most elements a single JSON-RPC batch may carry. Each one takes the
#: session lock and may reach a remote judge, so an unbounded batch is an
#: amplification vector against the gateway rather than against the server.
MAX_BATCH = 256

#: The one method this proxy authorizes. Compared exactly.
TOOL_CALL = "tools/call"

#: Argument names the floor recognises without a declaration. Kept here as well
#: as in `policy` so the proxy does not depend on a policy object being present.
DEFAULT_PATH_ARGS = ("file_path", "path", "filename", "file")

#: A path carrying any of these is refused before the scope is consulted. Each
#: is a way of writing a path that means one thing to this gateway and something
#: else to whatever finally opens the file, and a scope check is only as good as
#: the agreement between the two.
_PATH_POISON = ("\x00", "%2e%2e", "%2E%2E", "%2f", "%2F", "%5c", "%5C")

#: JSON-RPC application error code returned for a policy refusal. -32000 to
#: -32099 is the range the spec reserves for implementation-defined server
#: errors, so a compliant client surfaces it as an error rather than choking.
POLICY_DENIED = -32001


@dataclass
class ProxyStats:
    forwarded: int = 0
    denied: int = 0
    stepped_up: int = 0
    malformed: int = 0
    hidden_tools: set[str] = field(default_factory=set)

    def summary(self) -> str:
        line = (f"clayseal proxy: {self.forwarded} allowed, {self.denied} denied, "
                f"{self.stepped_up} held for approval")
        if self.malformed:
            line += f", {self.malformed} malformed"
        if self.hidden_tools:
            line += f"; withheld from the catalog: {', '.join(sorted(self.hidden_tools))}"
        return line


@dataclass
class McpProxy:
    """Enforce a compiled policy between an MCP client and an MCP server.

    `gateway` is anything with `.authorize(Action) -> decision`, which both
    `SessionBroker` and `DeployableStack` are.
    """

    gateway: Any
    allowed_tools: set[str] | None = None
    #: `tools.patterns` from the policy, UNIONed with `allowed_tools`. Both
    #: gates below consult it, because a catalog filter that disagrees with
    #: the call check is worse than either: the agent is told a tool does not
    #: exist and then allowed to call it, or is offered one and refused.
    tool_patterns: list[str] | None = None
    #: tool -> verb, declared by the operator in the policy document. The
    #: name-based classifier is a fallback and it is wrong on most real MCP
    #: catalogs: measured against 24 tool names taken from widely used servers,
    #: 17 fall through to `call`, including `terraform_destroy`, `grant_role`,
    #: `s3_put_object` and `disburse_funds`. `call` is the conservative answer
    #: rather than a wrong one, but it is not the verb, and the floor's write and
    #: egress rules key off the verb. An operator who names them gets the rules.
    tool_verbs: dict[str, str] = field(default_factory=dict)
    #: tool -> the argument carrying the path it acts on. The floor looks for
    #: `file_path`, `path`, `filename` and `file`; a tool whose argument is named
    #: `target_dir` or `key` yields no path, so the path scope is skipped and the
    #: write is allowed. Declaring the argument puts it back on `meta["path"]`,
    #: which is the field the floor prefers.
    path_args: dict[str, str] = field(default_factory=dict)
    #: Tools asserted to act on no path. Distinguishes "has no path" from "nobody
    #: said what its path argument is called", which must not look the same.
    pathless_tools: frozenset[str] = field(default_factory=frozenset)
    #: Whether an effectful call whose path cannot be resolved, while a path scope
    #: is configured, is refused. The gateway cannot apply the scope to it, and a
    #: control that cannot be applied must not report success.
    require_resolvable_path: bool = True
    #: Hold an EFFECTFUL call until the results of earlier calls have arrived.
    #:
    #: MCP clients may pipeline: an agent can issue a read and a send before
    #: either answer comes back. When it does, the send is authorized before the
    #: read's result reaches `observe_output`, so the provenance tier is asked
    #: about a destination it has not been told the origin of, and answers as if
    #: the document had never been read. The floor and the budgets are unaffected
    #: because they do not depend on ordering; every tier that reads returned
    #: content does.
    #:
    #: Reads are never held. Waiting is bounded by `settle_timeout` and expiry is
    #: fail-open on ORDERING only, which forfeits an advisory rather than a
    #: control, and is logged.
    #:
    #: It waits only when results are known to be coming back, which
    #: `run_stdio_proxy` declares and `handle_server_message` proves. A caller
    #: that drives `handle_client_message` and never feeds results is not made to
    #: sit through the timeout on every effectful call: there is nothing to wait
    #: for, and turning that into a 15-second stall would be the same class of
    #: trap this file exists to remove.
    serialize_effects: bool = True
    settle_timeout: float = 15.0
    #: Where to report refusals. Defaults to stderr, because stdout is the
    #: protocol and one stray print corrupts the stream.
    log: Callable[[str], None] | None = None
    #: Feed tool RESULTS back into the gateway. Without this the proxy runs the
    #: floor and the budgets and nothing else: the provenance, taint and session
    #: tiers all read what came back from a tool, and through the proxy nothing
    #: ever came back. Off only for a gateway that does not want it, because a
    #: result is content and the gateway will hash and inspect it.
    observe_results: bool = True
    stats: ProxyStats = field(default_factory=ProxyStats)
    _step: int = 0
    _initializations: int = 0
    #: request id -> tool name, for calls forwarded and not yet answered. This is
    #: the only way to attribute a response to the tool that produced it: MCP
    #: responses carry the id and not the method.
    _in_flight: dict[Any, str] = field(default_factory=dict, repr=False)
    _lock: Any = field(default_factory=threading.Lock, repr=False)
    _settled: Any = field(default=None, repr=False, compare=False)
    #: Set once anything proves results flow back into this proxy.
    _results_channel_live: bool = False

    @classmethod
    def from_policy(cls, policy: Any, gateway: Any = None, **overrides: Any):
        """Build a proxy that enforces `policy`, wired correctly.

        Five fields have to agree with the document, and getting one wrong is
        silent in the direction that matters: a proxy built without
        `pathless_tools` refuses every effectful call that carries no path,
        with a message about a declaration the document already made. That
        wiring lived in `cli.py`, so the CLI was correct and every other caller
        was on their own, which is the shape of defect this repository keeps
        finding. It lives here now and the CLI calls it.
        """
        return cls(
            gateway=policy.build() if gateway is None else gateway,
            allowed_tools=policy.allowed_tools,
            tool_patterns=policy.tool_patterns,
            tool_verbs=dict(policy.tool_verbs),
            path_args=dict(policy.path_args),
            pathless_tools=policy.pathless_tools,
            **overrides,
        )

    def __post_init__(self) -> None:
        # A Condition over the same lock, so "is anything outstanding" is read
        # and waited on atomically.
        self._settled = threading.Condition(self._lock)

    def new_session(self, gateway: Any = None) -> None:
        """Start a new session: fresh budgets, fresh trajectory, fresh totals.

        Call this from your control plane when a task ends. It is not reachable
        from the protocol on purpose; see the module docstring.

        Pass `gateway` to swap in one built from a different policy, which is how
        a long-lived proxy serves tasks with different goals.
        """
        with self._settled:
            if gateway is not None:
                self.gateway = gateway
            self._in_flight.clear()
            self._step = 0
            self.stats = ProxyStats()
            self._settled.notify_all()

    def _note(self, message: str) -> None:
        (self.log or (lambda m: print(m, file=sys.stderr, flush=True)))(message)

    # ------------------------------------------------------------------ #
    # The decision
    # ------------------------------------------------------------------ #
    def _action_for(self, params: dict[str, Any]) -> Action:
        tool = str(params.get("name") or "")
        args = params.get("arguments")
        args = dict(args) if isinstance(args, dict) else {}
        with self._lock:
            step = self._step
            self._step += 1
        paths = self._path_candidates(tool, args)
        meta: dict[str, Any] = {"path": paths[0]} if paths else {}
        return Action(
            step=step,
            tool=tool,
            resource=f"mcp:tool:{tool}",
            verb=self.tool_verbs.get(tool) or classify_verb(tool),
            args=args,
            meta=meta,
        )

    def _path_candidates(self, tool: str, args: dict[str, Any]) -> list[str]:
        """EVERY path this call names, not the first one found.

        Two bypasses live in "the first one found". A call carrying both the
        declared argument and a default one had only the declared one checked, so
        `{"target_dir": "infra/staging/ok.tf", "path": "infra/prod/web.tf"}`
        cleared a scope that denies `infra/prod/**`. And a tool taking a LIST of
        files had one element checked and the rest ignored. Both are the same
        mistake: a single path stands in for a set.

        Declared names and the four defaults are unioned, and list values are
        flattened, so what comes back is the whole set the call acts on.
        """
        names: list[str] = []
        declared = self.path_args.get(tool)
        if isinstance(declared, str):
            names.append(declared)
        elif isinstance(declared, (list, tuple)):
            names.extend(str(n) for n in declared)
        names.extend(DEFAULT_PATH_ARGS)

        out: list[str] = []
        for name in names:
            for value in _flatten_strings(args.get(name)):
                if value and value not in out:
                    out.append(value)
        return out

    def _path_is_resolvable(self, action: Action) -> bool:
        return bool((action.meta or {}).get("path"))

    def _await_settled(self, tool: str) -> None:
        """Block until no tool result is outstanding, or the timeout expires."""
        with self._settled:
            if not self._in_flight:
                return
            outstanding = sorted(set(self._in_flight.values()))
            if not self._settled.wait_for(
                lambda: not self._in_flight, timeout=self.settle_timeout
            ):
                self._note(
                    f"clayseal: {tool} proceeded without the results of "
                    f"{', '.join(outstanding)}, which did not arrive within "
                    f"{self.settle_timeout:g}s. The provenance and taint tiers "
                    f"were not told what those calls returned."
                )

    def _scope(self):
        """The gateway's path scope, or None."""
        broker = getattr(self.gateway, "broker", self.gateway)
        scope = getattr(broker, "scope", None)
        if scope is None or not (getattr(scope, "allowed_paths", None)
                                 or getattr(scope, "denied_paths", None)):
            return None
        return scope

    def _path_refusal(self, action: Action) -> str | None:
        """Why this call's paths are not acceptable, or None if they are.

        The broker checks ONE path per action, which is correct for the action
        model and insufficient for a tool call that names several. This screens
        the whole set before the action reaches it, so the answer is about the
        call rather than about whichever path happened to be first.
        """
        from clayseal.capabilities.hardening.protected_zones import protected_reason
        from clayseal.core.task_scope import task_scope_allows_path

        candidates = self._path_candidates(action.tool, action.args)

        for path in candidates:
            poison = next((p for p in _PATH_POISON if p in path), None)
            if poison is not None:
                return (
                    f"path {path!r} contains {poison!r}. A path that has to be "
                    f"decoded or truncated before it means anything cannot be "
                    f"checked against a scope, because this gateway and whatever "
                    f"opens the file would be checking different strings."
                )

        scope = self._scope()
        if scope is None:
            return None

        if not candidates:
            if not self.require_resolvable_path or action.verb in ("read", "call"):
                return None
            # The scope exists and cannot be applied to this call, so the call is
            # unverified rather than permitted. Silently skipping the check is how
            # a policy that denies `infra/prod/**` allows a write to
            # `infra/prod/main.tf` because the tool named the argument
            # `target_dir`.
            return (
                f"the path scope cannot be applied to {action.tool!r}: no path "
                f"argument was found. Declare it under paths.arg_names, or list "
                f"the tool under paths.pathless if it acts on no path."
            )

        for path in candidates:
            reason = protected_reason(path)
            if reason:
                return reason
            if not task_scope_allows_path(scope, path):
                return f"path {path!r} outside scope"
        return None

    def _tool_granted(self, name: str) -> bool:
        """One predicate for both gates, so they cannot drift apart.

        Only a document that scopes NEITHER dimension admits everything. The
        first draft asked `allowed_tools is None` after failing to match a
        pattern, which fails OPEN on the exact document this field exists for:
        patterns declared, no literal list, so every unmatched tool was granted.
        Caught by asserting the two gates agree.
        """
        if self.allowed_tools is None and self.tool_patterns is None:
            return True
        if self.tool_patterns:
            import fnmatch
            if any(fnmatch.fnmatch(name, p) for p in self.tool_patterns):
                return True
        return bool(self.allowed_tools) and name in self.allowed_tools

    def check(self, params: dict[str, Any], *, request_id: Any = None) -> tuple[bool, str]:
        """Decide one `tools/call`. Returns (allowed, reason)."""
        action = self._action_for(params)
        if not self._tool_granted(action.tool):
            self.stats.denied += 1
            return False, (
                f"tool {action.tool!r} is not in this session's policy"
            )
        if (self.serialize_effects and self._results_channel_live
                and action.verb not in ("read", "call")):
            self._await_settled(action.tool)
        if action.tool not in self.pathless_tools:
            refusal = self._path_refusal(action)
            if refusal is not None:
                self.stats.denied += 1
                return False, refusal
        decision = self.gateway.authorize(action)
        reasons = "; ".join(getattr(decision, "reasons", ()) or ()) or "no reason given"
        if getattr(decision, "allowed", False):
            self.stats.forwarded += 1
            if request_id is not None:
                with self._settled:
                    self._in_flight[_key(request_id)] = action.tool
            return True, reasons
        # `SessionBroker` returns an `Outcome` and `DeployableStack` returns the
        # same value as a plain string. Comparing with `is Outcome.STEP_UP` was
        # true for the first and false for the second, so through the CLI, which
        # builds a stack, every step-up was reported to the agent as a flat
        # denial and the counter stayed at zero. Normalise once instead.
        if _outcome_name(decision) == "step_up":
            # A step-up is not an allow. Nothing here can hold a call open while
            # a human is asked, so the honest answer to the agent is "refused,
            # and a person has to authorize it", not a silent pass.
            self.stats.stepped_up += 1
            return False, f"held for human approval: {reasons}"
        self.stats.denied += 1
        return False, reasons

    # ------------------------------------------------------------------ #
    # The stream
    # ------------------------------------------------------------------ #
    def _refusal(self, msg: dict[str, Any], tool: Any, reason: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": msg.get("id"),
            "error": {
                "code": POLICY_DENIED,
                "message": f"refused by policy: {reason}",
                "data": {"tool": tool, "gateway": "clayseal"},
            },
        }

    def _decide_one(self, msg: Any) -> tuple[Any | None, dict[str, Any] | None]:
        """Decide one JSON-RPC object. Returns (to_server, refusal_or_None)."""
        if not isinstance(msg, dict):
            return msg, None
        method = msg.get("method")
        if method == "initialize":
            # The client believes it is starting fresh. The gateway is not, and
            # that difference is worth saying out loud rather than letting the
            # operator discover it as a budget that ran out for no visible
            # reason. Resetting here instead would hand the agent its own reset.
            with self._lock:
                self._initializations += 1
                nth = self._initializations
            if nth > 1:
                self._note(
                    "clayseal: the client re-initialized, and session state is "
                    "NOT reset by that. Budgets, totals and the trajectory carry "
                    "over. Call new_session() from your control plane if this is "
                    "meant to be a new task."
                )
            return msg, None
        if method != TOOL_CALL:
            if isinstance(method, str) and method.strip().lower() == TOOL_CALL:
                # Close enough to be a tool call for a lenient server and not
                # close enough for this one. Forwarding it would mean betting
                # that the server is exactly as strict about the string.
                raise MalformedMessage(
                    f"method {method!r} is not exactly {TOOL_CALL!r}"
                )
            return msg, None

        params = msg.get("params")
        params = params if isinstance(params, dict) else {}
        allowed, reason = self.check(params, request_id=msg.get("id"))
        if allowed:
            return msg, None
        tool = params.get("name")
        self._note(f"clayseal DENY {tool}: {reason}")
        # A JSON-RPC NOTIFICATION carries no id, and the spec forbids answering
        # one. Refusing it still has to stop it, so the call is dropped and no
        # reply is invented; the agent learns nothing, which is what a
        # notification means.
        if "id" not in msg:
            return None, None
        return None, self._refusal(msg, tool, reason)

    def handle_client_message(self, raw: str) -> tuple[str | None, str | None]:
        """One line from the client.

        Returns `(to_server, to_client)`. For a tools/call, either it is
        forwarded or it is answered here and the server never sees it.

        What is forwarded is re-serialised from what was parsed, not the original
        bytes. See the module docstring: forwarding the original makes the
        gateway only as correct as the agreement between two JSON parsers.
        """
        try:
            msg = _strict_loads(raw)
        except MalformedMessage as exc:
            self._note(f"clayseal DENY (malformed): {exc}")
            self.stats.malformed += 1
            return None, json.dumps(self._refusal({"id": None}, None, str(exc)))
        except (ValueError, TypeError):
            return raw, None                      # not ours; do not eat it

        if isinstance(msg, list):
            if len(msg) > MAX_BATCH:
                self.stats.malformed += 1
                return None, json.dumps(self._refusal(
                    {"id": None}, None,
                    f"batch of {len(msg)} exceeds the {MAX_BATCH}-element limit"))
            forward, refusals = [], []
            for item in msg:
                try:
                    keep, refusal = self._decide_one(item)
                except MalformedMessage as exc:
                    self.stats.malformed += 1
                    refusals.append(self._refusal(
                        item if isinstance(item, dict) else {"id": None},
                        None, str(exc)))
                    continue
                if keep is not None:
                    forward.append(keep)
                if refusal is not None:
                    refusals.append(refusal)
            return (
                json.dumps(forward) if forward else None,
                json.dumps(refusals) if refusals else None,
            )

        try:
            keep, refusal = self._decide_one(msg)
        except MalformedMessage as exc:
            self._note(f"clayseal DENY (malformed): {exc}")
            self.stats.malformed += 1
            return None, json.dumps(self._refusal(msg, None, str(exc)))
        if keep is not None:
            return json.dumps(keep), None
        return None, json.dumps(refusal) if refusal is not None else None

    def settle(self, request_id: Any) -> None:
        """Mark one forwarded request answered, whatever id the reply carried.

        Over stdio the id is the ONLY correlation available: replies arrive
        interleaved on one stream and nothing else says which request they
        answer. Over HTTP the request itself is the correlation, one exchange
        per connection, and the id is a formality the server may get wrong.

        It does get it wrong, and the cost is not cosmetic. A server that echoes
        a mismatched id leaves the entry outstanding, so the NEXT effectful call
        waits out `settle_timeout` before proceeding: measured at 15 seconds per
        call, 30 seconds for three. That is an availability failure a malicious
        or merely non-compliant upstream can trigger deliberately, which is the
        same class this repository already flagged for an unbounded judge call.

        The HTTP front end calls this after it has the reply in hand. Nothing on
        the stdio path changes.
        """
        with self._lock:
            self._in_flight.pop(_key(request_id), None)
            if not self._in_flight:
                self._settled.notify_all()

    def handle_server_message(self, raw: str) -> str:
        """One line from the server.

        Two jobs. It feeds tool results back into the gateway, and it filters the
        advertised tool catalog.
        """
        try:
            msg = json.loads(raw)          # the server is trusted to be coherent
        except (ValueError, TypeError):
            return raw
        if isinstance(msg, list):
            for item in msg:
                self._absorb(item)
            return raw
        if not isinstance(msg, dict):
            return raw

        self._absorb(msg)

        if self.allowed_tools is None and self.tool_patterns is None:
            return raw
        result = msg.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return raw

        kept, dropped = [], set()
        for tool in result["tools"]:
            name = tool.get("name") if isinstance(tool, dict) else None
            if name is None or self._tool_granted(str(name)):
                kept.append(tool)
            else:
                dropped.add(str(name))
        if not dropped:
            return raw
        self.stats.hidden_tools |= dropped
        self._note(
            f"clayseal: withheld {len(dropped)} tool(s) from the catalog: "
            f"{', '.join(sorted(dropped))}"
        )
        result["tools"] = kept
        return json.dumps(msg)

    def _absorb(self, msg: Any) -> None:
        """Report one tool result to the gateway, if it was a tool result.

        This is what makes the provenance and taint tiers live behind the proxy.
        Without it the gateway sees a stream of requests and never sees a single
        answer, so `ParameterProvenance` has nothing to ground a destination
        against and every tier that reads returned content is inert. The floor and
        the budgets still worked, which is why the omission did not show up as a
        failing test: it showed up as tiers quietly doing nothing.

        Failures here are swallowed on purpose. A malformed or enormous tool
        result is the server's problem; it must not take down the proxy that is
        the only thing standing between the agent and the next call.
        """
        if not isinstance(msg, dict):
            return
        if "result" not in msg and "error" not in msg:
            return
        # A response arrived, so the channel is live and ordering can be waited
        # on. Recorded even when `observe_results` is off, because the ordering
        # guarantee and the content feed are separate decisions.
        self._results_channel_live = True
        if not self.observe_results:
            with self._settled:
                self._in_flight.pop(_key(msg.get("id")), None)
                if not self._in_flight:
                    self._settled.notify_all()
            return
        with self._settled:
            tool = self._in_flight.pop(_key(msg.get("id")), None)
            if not self._in_flight:
                self._settled.notify_all()
        if tool is None:
            return
        observe = getattr(self.gateway, "observe_output", None)
        if observe is None:
            return
        try:
            observe(tool, _result_text(msg.get("result")),
                    structured_fields=_structured_fields(msg.get("result")))
        except Exception as exc:  # noqa: BLE001 - see docstring
            self._note(f"clayseal: could not record the result of {tool}: {exc}")


def _result_text(result: Any) -> str:
    """MCP tool results are a `content` list of typed parts. Take the text."""
    if isinstance(result, str):
        return result
    if not isinstance(result, dict):
        return ""
    parts = result.get("content")
    if isinstance(parts, list):
        return "\n".join(
            str(part.get("text", ""))
            for part in parts
            if isinstance(part, dict) and part.get("type") == "text"
        )
    return json.dumps(result)[:100_000]


def _structured_fields(result: Any) -> dict[str, Any]:
    """Top-level scalars of MCP's `structuredContent`.

    The provenance tier separates a value that arrived in a STRUCTURED field of a
    tool output from one that appeared in free text, and treats only the first as
    a trustworthy origin. That distinction is the whole mechanism, so it has to
    be fed from the structured half of the response rather than from the prose.
    """
    if not isinstance(result, dict):
        return {}
    structured = result.get("structuredContent")
    if not isinstance(structured, dict):
        return {}
    return {
        k: v for k, v in structured.items()
        if isinstance(v, (str, int, float, bool))
    }


def run_stdio_proxy(
    proxy: McpProxy,
    command: list[str],
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> int:
    """Run `command` as an MCP server and mediate it. Returns its exit code."""
    stdin = stdin if stdin is not None else sys.stdin
    stdout = stdout if stdout is not None else sys.stdout

    server = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,                        # server diagnostics pass through
        text=True,
        bufsize=1,
    )

    def client_to_server() -> None:
        try:
            for line in stdin:
                line = line.rstrip("\n")
                if not line:
                    continue
                to_server, to_client = proxy.handle_client_message(line)
                if to_client is not None:
                    stdout.write(to_client + "\n")
                    stdout.flush()
                if to_server is not None and server.stdin is not None:
                    server.stdin.write(to_server + "\n")
                    server.stdin.flush()
        except (BrokenPipeError, ValueError):
            pass
        finally:
            # Closing the server's stdin is how an MCP server learns the session
            # ended. Without it the proxy exits and the server waits forever.
            if server.stdin is not None:
                try:
                    server.stdin.close()
                except OSError:
                    pass

    def server_to_client() -> None:
        try:
            if server.stdout is None:
                return
            for line in server.stdout:
                line = line.rstrip("\n")
                if not line:
                    continue
                stdout.write(proxy.handle_server_message(line) + "\n")
                stdout.flush()
        except (BrokenPipeError, ValueError):
            pass

    up = threading.Thread(target=client_to_server, name="clayseal-c2s", daemon=True)
    down = threading.Thread(target=server_to_client, name="clayseal-s2c", daemon=True)
    up.start()
    down.start()

    code = server.wait()
    down.join(timeout=2.0)
    proxy._note(proxy.stats.summary())
    return code
