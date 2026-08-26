# The shape a deployment actually has, and where this library does not fit it

STATUS: current

This document is the result of reading the MCP 2026-07-28 specification against
what this library assumes. Three of its assumptions are wrong for the transport
enterprises deploy, and one of them invalidates the deployment model of the
central mechanism. None of that is visible from any benchmark here, because
every benchmark replays a trajectory into a Python object and never speaks a
transport at all.

## 1. Sessions are gone, and the aggregate rung was anchored to them

MCP 2026-07-28 **removes the `initialize`/`initialized` handshake and the
`Mcp-Session-Id` header**. The stated reason is horizontal scale: any server
instance must be able to serve any request, with no sticky routing and no shared
session store.

Almost everything in this library is scoped to a session. `SessionBroker` is
"one live per-session gateway". `SessionValueBudget` is documented as "one
instance per session (the instance *is* the session's ledger)". `mcp_proxy`
states the model in its own header: "One proxy process is one session."

That model is correct for stdio, where the proxy owns a subprocess and the
process boundary is the session boundary. It has no meaning for Streamable HTTP
behind a load balancer, where consecutive tool calls from one agent may land on
different instances and nothing carries between them.

**The consequence is specific and it is not a degradation.** A per-session
ceiling in a stateless deployment is not a weak control an attacker has to work
to reset. It resets by itself, on every request, and the aggregate rung this
library exists for is inert. `benchmarks/results/aggregation_residual.md` already
measured the session-restart escape and `principal_ledger.py` was built to close
it; what the spec change does is turn that from an attack into the default.

**Fixed.** A policy declares the anchor and the ceiling moves off the session:

```yaml
deployment:
  stateless: true
  principal: acct-9
  ledger: {path: /var/lib/clayseal/ledger.jsonl, window_seconds: 86400}
```

`PrincipalBudgetView` now has the `reserve(tool, args)` the broker calls, and it
does not re-implement the session budget: `parse_amount` moved to module level
so there is one answer to "how much does this call move", and the tri-state it
returns is preserved, so a tracked-but-unreadable amount still fails closed
rather than reading as untracked.

Two properties had to survive a PROCESS boundary rather than a session one, and
only the first did at the first attempt. The ceiling held; **once-per-object did
not**, because identity lived in memory and a second process paid the same
invoice again. Identity is now checked inside `PrincipalLedger.reserve` under
the same lock as the ceiling, persisted on the ledger entry, and rebuilt on
load. A released or expired hold gives the object back, so one refusal is not a
permanent one.

A stateless deployment with an in-memory principal ledger is **refused at
compile time**: it dies with the process, a stateless deployment is many
processes, and the ceiling would still reset. `session-scoped-ceiling` is an
error rather than a warning wherever `stateless: true` is declared.

## 2. A gateway that routes on headers authorizes a different call than executes

SEP-2243 adds `Mcp-Method` and `Mcp-Name` to the Streamable HTTP transport
specifically so that "load balancers, gateways, and rate-limiters can route on
the operation without inspecting the body."

The spec is careful about the resulting ambiguity: the **body is the source of
truth**, servers MUST validate that the headers match it, and a disagreement is
rejected with `-32020`.

Note who that duty falls on. **Servers** validate. A security gateway placed in
front, which is what this library is, is the intermediary being invited to skip
the body. If it authorizes `Mcp-Method: tools/list` while the server executes a
`tools/call` for a money-moving tool, the gateway approved an operation that
never ran and the one that ran was never checked.

This repository has already closed one bug of exactly this class: duplicate JSON
keys, where Python keeps the last and other parsers keep the first, so the
gateway and the server read different arguments from one message. A header that
disagrees with the body is the same defect promoted to the transport layer, and
it is now a documented part of the protocol rather than a quirk.

**Fixed.** `agentauth/capabilities/http_gateway.py` is the front end, and
`clayseal serve --policy p.yaml --upstream https://...` runs it. It wraps
`McpProxy` rather than re-implementing the decision path, so the duplicate-key,
near-match and batch refusals already measured there apply unchanged, and it
adds the transport rule: **the body is authorized, always.** Headers are checked
for agreement and never consulted for a decision. A disagreement is `-32020`
before any authorization runs, a batch carrying routing headers is refused
because one pair cannot describe several messages, and the headers forwarded
upstream are regenerated from the forwarded body rather than copied, so an
attacker's header is not handed on to a server that trusts it.

Standard library only: `http.server` and `urllib`. The dependency count stays at
two, which is a large part of why this is installable at all.

**What is live without a session, reported rather than inferred.**
`GET /mcp/readiness` answers it. The floor is live, since scope, protected
zones, egress and tool admissibility are pure functions of one action and the
grant. Aggregates are live only against a principal ledger. The trajectory tiers
are **inert**: the intent envelope and the behavioural detector read a sequence
and a stateless request has none, so they are reported that way rather than run
against a trajectory of length one. An operator reading a quiet log cannot tell
a tier that found nothing from a tier that never ran.

## 3. Audit records do not join to anything

With sessions removed, the migration guidance is explicit that **W3C Trace
Context is "the correlation spine that replaces the session for audit"**, and
that "correlation is manufactured now, budget for it".

**Fixed.** `agentauth/capabilities/trace.py` parses a `traceparent`, the HTTP
gateway reads one per request, `Guardrail.trace()` takes one in process, and the
`trace_id` lands on every decision record as the join key.

Two properties made it worth doing carefully rather than quickly.

**The hash chain is unchanged for a record without a trace.** The field appears
in the hashed body only when present, so a log written before this exists still
verifies. The chain IS the evidence, and re-hashing every historical record to
add an optional field would invalidate the thing the field is there to serve.

**A malformed header is dropped rather than stored.** It arrives from outside
and may be anything. Nothing is authorized on the strength of a trace id, so it
is not a security boundary, but a log is evidence: a 4KB `tracestate` in every
record is a storage attack, and an unvalidated `traceparent` puts whatever the
sender wrote in the middle of a signed receipt. A record with no trace is
honest; one carrying a join key nobody can follow is a field that looks like
evidence and is not.

## What this does not change

The enforcement floor, the path scope, the budgets and the envelope are all pure
functions of an action and some state. None of them cares what transport
delivered the action, and the fuzzing in `stress_scope.md` and
`stress_surface.md` holds regardless. What the transport decides is **what a
session is**, and therefore what an aggregate is counted over. That is a
deployment question this library answered once, for stdio, in its own header
comment, and the answer changed underneath it.

## Sources

- MCP 2026-07-28 release candidate, statelessness and SEP-2243:
  https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/
- SEP-2243, HTTP header standardization:
  https://modelcontextprotocol.io/seps/2243-http-standardization
- Governance implications of the migration for permissions and audit:
  https://aaif.io/blog/governance-as-infrastructure-what-the-mcp-2026-07-28-migration-actually-demands-of-permissions-a
