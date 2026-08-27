# The policy document

STATUS: current

The whole grant, in one reviewable file. This is the reference; the annotated
starting point is [examples/policy.yaml](../examples/policy.yaml).

```bash
clayseal policy show policy.yaml     # what it authorizes
clayseal policy lint policy.yaml     # what a reviewer should ask about
clayseal proxy --policy policy.yaml -- npx @your-org/mcp-server
```

## Why a document rather than a constructor call

`SessionBroker` has 48 fields and `DeployableStack.from_goal` takes fourteen
posture switches. A security team cannot review that. They can review a file,
attach it to a change ticket, diff it in a pull request, and gate a merge on
`clayseal policy lint`.

The split this keeps is the one `profiles.py` already draws:

- a **profile** decides how the gateway behaves when the grant is silent.
- a **policy** is the grant.

A profile switch passed at the call site is refused, so a deployment cannot
quietly run a different posture than the document names.

## The document

Every section is optional except `version` and `goal`. An absent section means
the gateway has no authority to check there, which `lint` reports rather than
assuming was intentional.

### `version` (required)

```yaml
version: 1
```

A document without one is refused, and so is a version this build does not know.
An authority document read under the wrong schema grants whatever the reader
happened to understand.

### `goal` (required)

```yaml
goal:
  id: billing-triage-2026-08
  summary: >-
    Triage the open billing tickets, write a summary to out/summary.md, and
    email it to the operations archive.
```

`id` identifies the session. `summary` is load-bearing: the provenance roots, the
content checks, and any plan an envelope is compiled from all derive from it.
Write it as the task rather than as a category. `lint` reports an empty summary as
an error because it silently disables those tiers.

### `profile`

```yaml
profile: supervised          # autonomous | supervised | benchmark
```

What happens to an action the floor cleared and the plan did not predict.

| profile | behaviour | when |
| --- | --- | --- |
| `autonomous` | refuse it | nobody is watching; highest containment, lowest utility |
| `supervised` | ask about it | a person is on the escalation path, and the audit budget bounds how often they are interrupted |
| `benchmark` | what every published number was measured under | reproducing a result, not deploying |

An unknown name is refused rather than defaulted, because there is no safe
posture to fall back to when the operator's intent is unreadable.

### `expires_at`

```yaml
expires_at: 2026-12-31T00:00:00Z
```

ISO 8601. Absent means the grant authorizes forever, which `lint` warns about. An
unparseable value is refused at compile time, because an expiry that cannot be
parsed counts as expired and would deny everything.

### `tools`

```yaml
tools:
  allow:    [list_tickets, read_ticket, write_summary, send_email]
  harmless: [list_tickets, read_ticket, write_summary]
  effects:
    write_summary: write
    send_email: send
```

`allow` is the tool grant. Under the proxy it is also a catalog filter: tools
outside it are removed from `tools/list`, so the agent does not plan around a tool
it will then be refused.

`effects` says what each tool does, as one of `read`, `write`, `send`,
`transfer` or `call`. **Declare this for any catalog that does not read like a
list of verbs.** Without it the verb is guessed from the name, and the guess is
tuned on benchmark catalogs that do not look like real ones: of 24 tool names
taken from widely used MCP servers, 17 fall through to `call`, including
`terraform_destroy`, `grant_role`, `s3_put_object` and `disburse_funds`. `call`
is the conservative answer rather than a wrong one, and it is still not the verb,
and the floor's write and egress rules key off the verb. `clayseal policy lint`
names every tool it had to guess at.

`harmless` is an assertion by a person that a tool has no side effect worth
counting. The mandate linter cannot tell a read from a write by name, so this is
where that judgement goes, in the file that gets reviewed. A tool that is
effectful, reachable, and neither budgeted nor declared harmless is an error under
`autonomous` and `supervised`, and the gateway refuses to build. Naming a tool
harmless that is not in `allow` is refused, because it hides a typo as an
assertion.

#### `patterns`, when the grant is a family rather than a list

```yaml
tools:
  allow:    [cancel_booking]        # this tool
  patterns: ["get_*", "search_*"]   # and this family
```

`patterns` grants by shape. It is UNIONed with `allow`: a name in `allow` stays a
literal and nothing about an existing document changes meaning.

**Why it exists.** A grant assembled by enumerating what a session touched is not
a mandate, it is a log. An operator writes "the reservation tools"; the logger
writes the fourteen that happened to be called. Measured: rebuild a tau2 grant
from half a session's benign events and it refuses **47.91%** of the other half,
and every one of those refusals is `tool 'x' not granted` for a tool the same
session used, from the same catalog, that landed in the unobserved half. Writing
the grant as patterns takes that to **0.05%**. See
[generalisation.md](../benchmarks/results/generalisation.md).

**When not to use it.** This is a real trade and one corpus makes it vivid.
Generalising the tool grant to a namespace:

| corpus | held-out false-block | containment |
| --- | --- | --- |
| AgentHarm | 55.56% → **0.82%** | 27.16% → 25.86% |
| RedCode | unchanged | 99.86% → 99.86% |
| **Mind2Web-SC** | — | **98.00% → 0.00%** |

Mind2Web-SC collapses because its containment *is* the exact resource, minted
from the principal's attested attributes: generalising the grant admits
everything. If your containment rests on naming exact instances, patterns will
take it away. If your friction comes from a grant that could not enumerate
tomorrow's legitimate call, they will fix it. Know which you have before you
write one.

**Guards.** A universal pattern (`*`, `**`) is refused at compile time, the same
rule `paths.allow` carries: a grant of everything is not reviewable. An entry
with no wildcard is refused too, because a literal belongs in `allow` where a
reader can see it is one tool and not a family. `lint` always reports a pattern
grant, because it is the one part of the document whose extent is not visible
from reading it, and separately flags a leading wildcard: `*_data` admits
`delete_data` as readily as `read_data`.

Under the proxy, patterns filter the advertised catalog exactly as `allow` does,
through the same predicate, so the tools the agent is offered and the tools it
may call cannot drift apart.

### `paths`

```yaml
paths:
  allow: ["infra/staging/**"]
  deny:  ["infra/prod/**", "*.tfstate", ".env"]
  arg_names:
    tf_apply: target_dir       # which argument carries the path
    s3_put_object: key
  pathless: [slack_post_message]
```

Denies win over allows. These are on top of the built-in protected zones, which
already cover credentials, SSH material, and version-control internals. A
universal pattern in `allow` is a lint error: it grants the filesystem and makes
the rest of the section decorative.

**`arg_names` is the one most people need and nobody expects.** The gateway finds
an action's path by looking at four argument names: `file_path`, `path`,
`filename`, `file`. A tool that calls its argument `target_dir`, `key`,
`workspace` or `dir` yields no path at all, and a path scope that cannot find a
path is a path scope that does not apply. Before this section existed, a policy
denying `infra/prod/**` allowed a write to `infra/prod/web.tf` because the tool
named the argument `target_dir`, and nothing anywhere said a control had been
skipped.

Two things follow, and both are deliberate:

- Map the argument for every effectful tool whose schema does not use one of the
  four default names.
- An effectful call whose path cannot be resolved, while a path scope is
  configured, is **refused** by `clayseal proxy` rather than allowed unchecked.
  The gateway cannot apply the scope to it, so the call is unverified, and an
  unverified action is not a permitted one.

`pathless` is how you say a tool genuinely acts on no path. Without it there is
no way to distinguish "this tool has no path" from "nobody said what its path
argument is called", and the second one must not be treated as the first.

`clayseal policy lint` reports undeclared effectful tools as a **warning** rather
than an error, because a document cannot tell whether a tool uses a default
argument name. The runtime sees the actual arguments and is the control.

**In-process callers get no such check.** When you call `authorize()` yourself,
set `meta={"path": ...}` on the `Action`, or make sure the argument is one of the
four default names. The proxy does this from `arg_names`; nothing does it for
you.

### `egress`

```yaml
egress:
  domains:    [acme-internal.com]
  recipients: [ops@acme-internal.com]
  self:       [agent@acme-internal.com]
  bind_recipients: true
  allow_all: false
```

Where this session may send anything. A destination not listed is refused,
including one the agent read out of a document it was allowed to read, which is
the shape prompt injection takes when the floor is working. Domains and
recipients are lowercased on compile, since a destination check that is case
sensitive is one an attacker passes by capitalising.

**A domain matches itself and everything under it.** `acme-internal.com` allows
`mail.acme-internal.com` and `anything.acme-internal.com`. That is usually what
people mean and it is occasionally not: if any subdomain of the listed name can
be registered or controlled by someone else, the allow-list is wider than it
reads. Listing a public suffix is a lint error for this reason, because
`amazonaws.com` or `vercel.app` allows most of the internet while looking like an
allow-list.

It does **not** match a name that merely ends in the same characters:
`acme-internal.com.evil.example` is refused, and so is `xacme-internal.com`.

`bind_recipients` requires that an action carrying a destination actually had it
checked, so "no destination to check" and "destination on the allow-list" stop
looking the same in the audit trail.

`allow_all` is a lint error. It disables destination checking entirely.

### `budgets`

The control per-call authorization cannot express.

```yaml
budgets:
  calls:
    ceilings: {emails: 3}
    tracked:  {send_email: emails}

  value:
    ceilings: {refunds: "5000.00"}
    tracked:
      issue_refund: {arg: amount, budget: refunds}
```

`calls` counts calls; `value` accumulates an amount read from a named argument.
Value ceilings are strings so a currency amount is never accumulated as a float.

### A rolling window

```yaml
budgets:
  value:
    ceilings: {refunds: "5000.00"}
    windows:  {refunds: 86400}          # rolling 24 hours, in seconds
    tracked:
      issue_refund: {arg: amount, budget: refunds}
```

Without `windows`, a ceiling is **session-cumulative**: it means "no more than
$5,000 for the life of this gateway". With one, it means "no more than $5,000 in
any 24-hour period", which is the shape almost every written business rule takes.

The two are not interchangeable and the difference is not conservative. A session
ceiling standing in for a rolling one refuses legitimate work that a rolling
window would allow, and it accepts a sequence a rolling window would refuse
whenever the session is short. `grant_changes_2026_08.md` records the measured
case: a benign script that paid $2,000, waited 24 hours and paid $2,000 again was
refused by a session ceiling and is allowed by a window, while the attack that
waited only 6 hours is refused by both, for the right reason only under the
window.

An entry ages out of the window with its object identity, so `identity_args` on a
windowed budget means "once per object per window" rather than "once per object
ever". A window of zero or less is refused at compile time: it evicts everything
immediately and keeps looking like a ceiling.

### A conditional ceiling

```yaml
budgets:
  value:
    ceilings: {payout: "15000.00"}
    when:
      - if: {rush: true}
        ceilings: {payout: "5000.00"}
        reason: rush handling collapses the ceiling
      - if: {vendor_new: true}
        ceilings: {payout: "2000.00"}
```

Real authorities are not constants. A payout limit collapses when the request is
expedited, a trading limit tightens once a position is open, a retention window
shortens when a hold notice arrives.

**A guard may only tighten.** A guarded ceiling above the base one is refused at
compile time, and that restriction is the whole security argument rather than
caution. A condition is a fact about the session, facts arrive from tool output,
and tool output is content an attacker may control. If a guard could raise a
ceiling then `expedited: false` injected into a document would widen authority,
and the rung would be a lever for the attacker rather than a control on them.
Monotone tightening removes that: an attacker with full control of every
condition can only shrink the authority of the agent they have compromised.

The limitation this imposes is real and worth stating rather than burying.
**"Normally 5,000, and 15,000 once a manager approves" cannot be written as a
guard.** Raising authority is what step-up is for, and a step-up needs a signed
approval bound to the specific action. A guard and a step-up are the two halves
of "conditional", split by direction, and the split is the security argument.

Two more rules, both about not letting an ordering accident decide an authority
question:

- When several guards fire at once, the **tightest** wins, not the last
  declared. The order a document happens to list them in cannot change a
  decision.
- A guard with no condition is refused: it applies always, which is a base
  ceiling written in the wrong place.

**Where facts come from.** Only the STRUCTURED fields of tool output, fed
automatically by `observe_output`. Free text never becomes a fact, which is the
same distinction the provenance tier already draws between a value that arrived
in a named field and one that appeared in prose. A fact that fails to land leaves
the base ceiling in force, and under the tightening rule that is the safe
direction.

Comparison is deliberately strict about types: a fact of `1` does **not** match a
condition of `true`, because `1 == True` in Python and an authority decision must
not rest on that. A comparison that raises fires the guard, since failing toward
a smaller ceiling has no symmetric risk to weigh against it.

### A count the gateway derives for you

Every ceiling above is one you wrote. Most deployments write none: measured on
eleven independently-authored corpora, **0 of 520 tasks declare a budget**, so a
rung that waits for a declaration is inert exactly where it is needed.

So the gateway also derives a bound from the sealed goal. A goal reading

> Triage the open billing tickets and email a summary to the operations archive.

accounts for **one** send, and a second one is held for approval. Nothing is
declared anywhere.

**It steps up, it does not deny.** The bound came from reading a sentence, and a
retry after a failed send is indistinguishable from a second send, so "you said
one and this is the second" is a reason to ask rather than to refuse. Hard denial
in this layer requires positive evidence of malice.

It is deliberately quiet. Three signals produce a bound, an iteration marker
("each", "every", "all") suppresses it, and a clause supporting two readings
yields none, because a bound nobody clearly stated must not exist. Most goals get
no bound at all, which is the correct answer for them.

**What it costs, measured.** On AgentHarm's in-surface attack population it
contains 8 more events of 507, and it interrupts 26 benign actions of 278, so
roughly three interruptions per additional catch. On `sleight` it contributes
nothing. The 82.8% this paragraph used to cite as the reason was an artifact:
that column was the envelope refusing every consequential action because it was
comparing two vocabularies that never intersect, and the corrected figure is
23.0% in-surface containment at zero benign cost. Every one of
those interruptions is a step-up and not a refusal, verified by re-running the
same corpus with step-ups treated as allows, so the cost is a person's attention
rather than a lost task
([derived_counts_measured.md](../benchmarks/results/derived_counts_measured.md)).

Whether that trade is worth it is a deployment decision, and it is **off by
default** because three interruptions per catch is not a default anyone should
be given silently. Turn it on with
`compile_envelope(goal, derive_counts=True)`.

#### Inferring the ones a sentence does not state

Optional, off unless you pass one, and it changes nothing about the above:

```python
from agentauth.capabilities.monitor.generation import compile_envelope
from agentauth.capabilities.monitor.multiplicity import default_multiplicity_inferrer

envelope = compile_envelope(
    goal,
    inferrer=default_multiplicity_inferrer(),   # None without credentials
).envelope
```

An inferrer proposes a count for a goal the deterministic reading could not
parse. Three rules make it safe to have in the loop at all:

- **It runs once, at seal time, on the goal text and nothing else.** It never
  sees tool output, a trajectory or an argument, so a proposal cannot be
  influenced by content the agent later reads. That is the planner privilege
  split: a model may appear in the control plane and never in the decision path.
- **It may never raise a bound the text supports.** Under the default
  `fill_gaps` mode it only fills a gap; under `tighten` it may also lower one.
  Neither can widen. A proposal that only shrinks authority is safe whoever
  wrote it.
- **Every failure means "cannot say".** No credentials, a timeout, a rate limit,
  a malformed answer: the bound falls back to the deterministic reading, which is
  the behaviour with no inferrer at all. It is bounded in wall clock for the same
  reason the entailment judge is.

Each bound carries where it came from, and the step-up reason says so:

```
send send_email occurrence 2 of a phase the sealed goal accounts for 1 time(s) [derived]
send send_email occurrence 2 of a phase the sealed goal accounts for 1 time(s) [inferred]
```

A step-up whose origin is unknown is not reviewable. `derived` a person can check
against the sentence; `inferred` they cannot, and they should know which they are
looking at.

### Once per object

```yaml
budgets:
  value:
    ceilings: {payroll: "11000.00"}
    tracked:
      pay_bonus:
        arg: amount
        budget: payroll
        identity: [employee, period]    # pay each row exactly once
```

A ceiling answers "is the total under the limit" and answers it correctly while
the same invoice is paid twice. `identity` names the arguments that identify the
OBJECT an effect lands on, and a second commit against the same identity is
refused. Both halves of "pay each row once, under ceiling" are real constraints
and a ceiling alone expresses one of them.

A tracked tool pointing at a budget id with no ceiling is refused at compile time.
The document would read as though the tool is bounded, the runtime would find no
ceiling, and the call would proceed, so an author reading the file would conclude
a control exists that does not.

Ceilings are per session by default, which `lint` warns about: a second session
gets a second ceiling. Bind them to `principal_ledger` when the limit is meant to
be an authority limit rather than a session limit.

### A rule about STATE rather than about an amount

```yaml
tools:
  allow: [get_order, cancel_order, modify_order, change_cabin]
  when:
    - if: {order_status: shipped}
      deny: [cancel_order, modify_order]
      reason: "an order can only be cancelled while its status is pending"
    - unless: {flown: false}
      deny: [change_cabin]
      reason: "cabin cannot be changed once a flight has been flown"
```

Measured on four `tau2-bench` policy documents, 469 lines of prose nobody here
wrote, **31% of the sentences that state a rule are state-conditional
prohibitions** and only 10% are numeric ceilings. A guarded ceiling expresses
none of the first class, because none of those rules is about an amount.

`when` withdraws tools as facts arrive, and facts are the same named, structured
values `budgets.value.when` reads: fields of tool output, never free text.

**A rule may only WITHDRAW.** The baseline is `tools.allow` and a rule subtracts
from it, so an attacker who fully controls every fact can only reduce what the
agent it has compromised may do. There is no admitting form and the compiler
refuses one: facts come from tool output, and an `admit-when` rule would let an
injected `status: pending` widen a grant. That is the same argument
`conditional_ceiling.py` makes about ceilings, applied to admissibility.

`unless` is how "only if" is written. An unconfirmed precondition **withdraws**,
because a precondition nobody has established is not one that has been met, so
the tool is refused until the fact arrives.

The limitation is the ceilings' limitation. "Only cancel if pending" enforces as
"deny cancel when the status is known and is not pending", so an adversary who
controls the status field avoids the withdrawal and gets the baseline authority,
which they had anyway. This binds drift and mistake. It does not bind an
adversary who owns the fact source, and `lint` cannot tell you which you have.

### A sub-limit inside a total

A written policy often nests one limit inside another: "total disbursements must
not exceed $50,000 in any rolling 24 hours" and, three sections later, "refunds
are limited to $5,000 per day in aggregate". A refund is a disbursement, so the
second is a sub-limit inside the first.

**This document holds one ceiling per tool and cannot express both.** `tracked`
maps a tool to a single budget id, so `issue_refund` debits the total or the
refund cap, never both.

The wrong reading is the tempting one. Giving each its own budget id looks like
it enforces both rules, and it enforces neither: $50,000 of payments plus $5,000
of refunds is $55,000 against a document that says $50,000, because the
aggregate ceiling is the SUM of the two ids rather than the smaller. `lint`
reports it as an error:

```
ERROR   split-aggregation-key    value: one effect family across 2 budget ids
        (payments<-pay_vendor; refunds<-issue_refund); the aggregate ceiling is
        the sum, not the smallest
```

Put every tool in the family on the **outer** limit, so the total is right, and
record that the inner one is not enforced here. A count ceiling often carries
most of what the sub-limit was protecting against, and it composes:

```yaml
budgets:
  value:
    ceilings: {payments: "50000"}       # 3.2, the real total
    windows:  {payments: 86400}
    tracked:
      pay_vendor:   {arg: amount_usd, budget: payments, identity: [invoice_number, period]}
      issue_refund: {arg: amount_usd, budget: payments, identity: [transaction_id]}
  calls:
    ceilings: {refund_count: 20}        # 4.2, which does bound refunds
    windows:  {refund_count: 86400}
    tracked:  {issue_refund: refund_count}
```

The comment recording what is unenforced belongs in the file. A reviewer
comparing this against the source document will look for 4.1 and needs to find
the reason it is absent, not its absence.

### `resources`

```yaml
resources:
  - repo://out/summary.md
```

Resource references the goal explicitly authorizes. They seed the provenance
roots along with the literals in the summary.

## The digest

```python
policy = load_policy("policy.yaml")
policy.digest()          # 'sha256:4499cca812...'
policy.build().policy_digest
```

A hash over the document as written, with keys sorted so reformatting is not a
change of authority and any change of value is. The gateway carries it, so an
audit trail says which authority produced a decision rather than only what the
decision was.

The digest is taken over the raw document rather than over what the compiler
understood. Those differ exactly when a key was ignored, which is the case a
digest most needs to catch, and `lint` reports ignored keys separately.

## Lint findings

`clayseal policy lint` exits 1 on any error. Errors mean the document authorizes
something its author almost certainly did not intend; warnings mean a control is
absent and the absence might be deliberate.

| code | level | meaning |
| --- | --- | --- |
| `goal-summary-empty` | error | the tiers that derive from the summary are disabled |
| `expired` | error | every action is denied |
| `egress-allow-all` | error | destination checking is off |
| `path-scope-universal` | error | the path scope grants everything |
| `untracked-effectful-tool` | error | an effectful tool debits no budget; the gateway will refuse to build |
| `unknown-keys` | warning | a key was ignored, so it is authority the author believes they granted |
| `no-expiry` | warning | the grant authorizes forever |
| `no-egress-policy` | warning | destinations are unchecked |
| `no-path-scope` | warning | file actions are bounded only by the protected zones |
| `no-tool-allowlist` | warning | any tool the agent can reach is in scope |
| `path-arg-not-declared` | warning | an effectful tool did not say which argument carries its path; the proxy refuses it at runtime unless the argument is one of the four defaults |
| `verb-not-declared` | warning | the verb was guessed from the name and came back `call`, meaning unrecognised |
| `session-scoped-ceiling` | warning | a second session gets a second ceiling |
| `unaccounted-tool` | warning | reachable, unbudgeted, and not declared harmless |

`lint` runs the same mandate linter the gateway refuses to build on, so it
reports what `build` would reject instead of leaving the author to find out from
a traceback.

## Session lifetime

Ceilings are spent over the life of one gateway. Under `clayseal proxy` that is
the life of the process, so a policy allowing three emails allows three emails in
**total**, not three per task. Decide which you meant:

- **One process per task.** Start the proxy with the task and stop it after. The
  ceilings mean exactly what the document says.
- **One long-lived process.** Ceilings are a rate limit on the whole connection.
  Size them for the connection.
- **Task boundaries from your control plane.** Call `McpProxy.new_session()` when
  a task ends, optionally passing a gateway built from a different policy.

`new_session()` is deliberately not wired to MCP's `initialize`. That message
arrives from the agent's side of the boundary, so resetting on it would let
anything that speaks the protocol clear its own budget by reconnecting, which is
the attack budgets exist to stop. The proxy logs a notice when a client
re-initializes, so the divergence is visible rather than surprising.

## What the proxy checks that the library does not

The declarations in this document are read by `clayseal proxy`. Some of what it
does with them has no equivalent when you call `authorize()` yourself, and the
difference is worth knowing before you choose the in-process path.

| check | proxy | in-process |
| --- | --- | --- |
| tool grant, capabilities, budgets, egress, protected zones | yes | yes |
| path scope on the ONE path the action carries | yes | yes |
| path scope on **every** path the call names | yes | no |
| refuse a call whose path cannot be resolved at all | yes | no |
| refuse an encoded or NUL-bearing path | yes | no |
| refuse a message with duplicate JSON keys | yes | n/a |
| filter the advertised tool catalog | yes | n/a |
| feed tool results to the provenance tier | yes | you call `observe_output` |
| hold an effectful call until earlier results arrive | yes | you order the calls |

Three of those are the difference between a control applying and a control being
skipped, so an in-process integration has to do the equivalent itself:

- Set `meta={"path": ...}` on the `Action`, and check every path the call names
  rather than one. The gateway checks the path it is given.
- Call `observe_context` for content the agent read and `observe_output` for what
  a tool returned, before authorizing whatever comes next.
- Do not authorize a consequential action while an earlier call's result is
  still outstanding. The content tiers are ordering-sensitive by construction.

## Getting the decisions to the people who watch for incidents

```python
from agentauth.capabilities.decision_sinks import (
    CompositeSink, OcsfSink, OtelSpanSink, RotatingJsonlSink)

stack.broker.receipt_sink = CompositeSink(sinks=[
    RotatingJsonlSink(path="/var/log/clayseal/decisions.jsonl"),  # the chain
    OcsfSink(inner=your_siem_client),                             # the SIEM
    OtelSpanSink(),                                               # the traces
])
```

`OcsfSink` re-shapes each record into an OCSF **API Activity** event, which is
what a security team already ingests. Shipping JSONL was not enough on its own:
nobody writes a bespoke parser for one vendor's log.

The mapping adds nothing the record did not carry. Arguments stay hashed, the
receipt and previous hashes travel so the chain is verifiable from the SIEM's
own copy, and the trace id travels so the event joins to the caller's trace. A
SIEM event that cannot be tied back to the receipt it came from is a rumour.

Severity and status say different things on purpose: a refusal is a **success**
of the control and a **failure** of the attempt, and `status_id` describes the
attempt.

`OtelSpanSink` emits one span per decision when an OpenTelemetry SDK is
installed and counts `unavailable` when it is not. It is optional by
construction, because two runtime dependencies is a large part of why this
library installs at all.

## Putting it in front of an agent that is not MCP-shaped

`clayseal proxy` and `clayseal serve` sit outside the agent. When the agent is
yours and in the same process, `Guardrail` wraps the tools instead.

```python
from agentauth.capabilities.guardrail import Guardrail, Refused, StepUpRequired
from agentauth.capabilities.policy import load_policy

guard = Guardrail.from_policy(load_policy("policy.yaml"))
tools = guard.wrap_all({"get_order": get_order, "pay_vendor": pay_vendor})

print(guard.ungoverned(tools))   # tools the policy does not name, before you run
```

A wrapped tool authorizes, calls, and reports the result back. A refused call
raises `Refused` and never runs; one that needs a person raises `StepUpRequired`
carrying the request. They are separate exceptions because a caller that treats
them alike turns a supervised deployment into an autonomous one, or into one
that cannot act at all.

There is deliberately no LangGraph adapter, no OpenAI Agents SDK adapter and no
CrewAI adapter. Each would import a framework this library does not otherwise
need and would break when that framework's tool interface changed. They all
agree that a tool is a **named callable taking keyword arguments**, so the
adapter is over that and the glue is one line you write:

```python
# LangChain / LangGraph
StructuredTool.from_function(guard.wrap("pay_vendor", pay_vendor))

# OpenAI Agents SDK
function_tool(guard.wrap("pay_vendor", pay_vendor))

# Anthropic SDK tool runner, or any hand-written loop
runner = client.beta.messages.tool_runner(tools=list(tools.values()), ...)
```

The wrapper keeps `__name__`, `__doc__` and the signature, because a framework
builds the schema the model sees from those and losing them changes the tool the
model sees, which is a behaviour change dressed as a security control. An async
tool stays async.

**Report the results.** It is on by default and it is the thing a hand-rolled
wrapper forgets: provenance, taint, the confidentiality tracker and every
`tools.when` fact read what a tool RETURNED. A benchmark run against a stack
with no result feedback once scored byte-identical to its floor rung, with every
observation-driven layer quiet rather than absent.

## Where the first draft comes from

Nobody should write this file from nothing. Two commands read the halves out of
what a deployment already has, and both write a **file a person finishes**
rather than a grant.

```bash
clayseal policy init --rules delegation_of_authority.md \
    -- npx @your-org/mcp-server > draft.yaml
clayseal policy lint draft.yaml
```

`policy init` runs the MCP server and asks it for `tools/list`. Out of the reply
come `tools.allow`, a guess at `tools.effects` from each name and description,
`paths.arg_names` from the input schemas, and `paths.pathless` for the tools
whose schemas show no path. `policy draft` reads a written business document and
produces the ceilings, windows, once-only rules, directories and allowed domains,
each citing the line it came from.

Three properties are what make the output reviewable rather than merely
plausible.

**Every rule cites its source line.** A reviewer checks a ceiling against the
sentence that set it, by line number.

**Nothing rule-shaped is dropped silently.** A sentence that reads like a rule
and did not translate becomes a `TODO` comment carrying its text. On a real
delegation-of-authority document one of those was "the person who prepares a
payment may not approve it", which this layer does not express at all, and the
comment is the only reason a reviewer learns that.

**The catalog may raise a tool's effect and never lower one.** The server
describing the tools is the server being constrained. A description that says
`transfer` where the name said `call` is taken; a description that says `read`
where the name said `write` is **reported and not applied**. For the same
reason, a tool that publishes no input schema is not written into
`paths.pathless`: the server did not say, which is not the same as the server
saying no.

What neither command fills in is `budgets.tracked`. The document knows the
ceiling and the catalog knows which argument carries the amount; which tool
debits which ceiling is in neither of them, and it is the decision the whole
aggregate rung rests on. Both are printed as commented suggestions.

## What the document deliberately does not hold

**The intent envelope.** It comes from a privileged planner that reads the goal
before any untrusted content exists (see
[intent_envelope_generation.md](intent_envelope_generation.md)). A hand-written
envelope in a YAML file is a plan the operator guessed at, and the guess is wrong
in the direction of over-permission every time. Pass one to `build()` when you
have it.

**Identity.** Who the agent is comes from your IdP through an
`IdentitySession`, not from this file.

**Keys.** Pinned signer keys come from the environment or the call site, so a
policy document can be committed to a repository without carrying key material.
