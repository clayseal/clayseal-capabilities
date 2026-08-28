# Clay Seal

<img src="docs/assets/clay-seal-logo.png" alt="Clay Seal logo" width="420">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%20%E2%80%93%203.14-blue.svg)](pyproject.toml)
[![Tests](https://img.shields.io/badge/tests-2900%2B%20passing-brightgreen.svg)](.github/workflows/ci.yml)
[![PyPI](https://img.shields.io/badge/pip-clayseal-orange.svg)](https://pypi.org/project/clayseal/)

**A policy gateway for AI agents. It stops the attack where every single call
is legitimate and the sequence is not.**

Your agent has a $1,000 refund ceiling. It issues eleven refunds of $900. Every
call is inside the per-refund limit, so every per-call check passes, and $9,900
goes out the door. Nothing that looks at one call at a time can see this.

Clay Seal sits in front of your tools and judges each call against the whole
session: the grant, the running totals, where the arguments came from, and what
the agent has already done.

## Install

```bash
pip install clayseal
```

Python 3.10 to 3.14. Two dependencies: `cryptography` and `pyyaml`.

## Use it in two lines

Wrap the tools you already have. Nothing else about your agent changes.

```python
from clayseal.capabilities import Guardrail, Refused, StepUpRequired

def list_open_refunds():
    return [{"invoice": "INV-001", "amount": 900.0},
            {"invoice": "INV-002", "amount": 900.0}]

def issue_refund(invoice, amount):
    return f"refunded {invoice} ${amount:.2f}"

guard = Guardrail.from_policy_file("examples/refund.yaml")
tools = guard.wrap_all({"list_open_refunds": list_open_refunds,
                        "issue_refund": issue_refund})

# Call them exactly as before. The gateway decides before the tool runs.
for row in tools["list_open_refunds"]():
    try:
        print(tools["issue_refund"](invoice=row["invoice"], amount=row["amount"]))
    except Refused as exc:
        print("refused:", exc.reasons)      # hand the reason back to the agent
    except StepUpRequired as exc:
        print("needs a human:", exc.reasons)
```

The first refund goes through. The second is refused, because the $1,000
session ceiling in `examples/refund.yaml` is already spent. Neither call
reached your function.

The wrappers keep the name, docstring and signature of your originals, so any
framework that introspects them sees the tool it saw before. That covers
LangGraph, the OpenAI Agents SDK, CrewAI and hand-written loops, because they
all agree that a tool is a named callable taking keyword arguments.

## Or put it in front of an MCP server

No code change at all. The gateway speaks MCP, so it sits between your agent and
the server:

```bash
clayseal proxy --policy policy.yaml -- npx @your-org/mcp-server
```

Tools the policy does not grant are removed from the catalogue, so the agent is
never told they exist.

## Write the policy

This is a whole policy. It lints clean.

```yaml
version: 1

goal:
  id: refund-run
  summary: Refund the invoices the customer disputed.

expires_at: 2027-12-31T00:00:00Z

tools:
  allow:    [list_open_refunds, issue_refund]
  harmless: [list_open_refunds]                 # a read spends nothing
  effects:  {list_open_refunds: read, issue_refund: write}

paths:
  pathless: [list_open_refunds, issue_refund]   # these act on invoices, not files

budgets:
  value:
    ceilings: {refunds: "1000.00"}              # dollars, for the whole session
    tracked:
      issue_refund: {arg: amount, budget: refunds}
```

Run `clayseal policy lint policy.yaml` before you ship. It catches the mistake
that matters most: a tool that can spend money but debits no budget. On the file
above it reports no errors and two warnings, both of which name a real decision
you have not made yet.

Full reference: [docs/POLICY.md](docs/POLICY.md).

## See it stop the attack

From a checkout. [examples/](examples/) has five, each runnable with no key and
no network:

```bash
python examples/02_the_proxy.py
```

```
tools advertised to the agent: list_open_refunds, issue_refund
  (the server offers wire_funds; the policy does not grant it, so the agent is never told it exists)

  ok   issue_refund       INV-001   paid INV-001 $900.00
  DENY issue_refund       INV-002   refused by policy: value_budget_exceeded
  ...
  DENY issue_refund       INV-011   refused by policy: value_budget_exceeded
  DENY wire_funds         ops-float refused by policy: tool 'wire_funds' is not in this session's policy

the server executed 2 call(s):
  list_open_refunds {}
  issue_refund {"amount": 900.0, "invoice": "INV-001"}

clayseal proxy: 2 allowed, 11 denied, 0 held for approval; withheld from the catalog: wire_funds
```

Read the last block. A JSON-RPC error proves the agent was told
no; the server's own ledger proves the refund did not happen, and those are
different claims. The same run on the command line, which is the deployment
shape a deployment actually uses:

```bash
clayseal proxy --policy examples/refund.yaml -- python examples/refund_server.py
```

## How it works

You give the gateway a **policy file** and a **goal** for the session. It seals
the goal at the start, so nothing the agent reads later can widen what was
approved. Every tool call then goes through one decision point before it runs.

A call gets one of three answers:

- **allow** and the call goes to the tool
- **step up** and the call waits for a person to approve it
- **deny** and the call never runs

Step-up exists because a wrong refusal is expensive. An autonomous attacker is
stopped just as hard by a call that waits for approval as by one that is
refused, and a legitimate agent is not stopped permanently. Denial is reserved
for cases with positive evidence of a problem.

The checks that produce those answers run in a fixed order, cheapest and
strictest first, so a call refused early never reaches the expensive layers.

1. **Floor.** The flat rules: has the grant expired, is this tool allowed, is
   this path in scope, is this destination on the egress list, is there budget
   left. Fastest and most of the denials.
2. **Declaration.** If the agent states a plan up front, the plan is checked
   against the sealed goal before any of it runs.
3. **Content.** Checks that a declared write matches the goal, and inspects the
   payload of a write that has an effect. Produces a step-up, never a denial.
4. **Session state.** Running totals, which values came from untrusted text,
   and any rules written against them.
5. **Provenance.** Where a destination came from. A payee named in the sealed
   goal is trusted; one that appeared in text the agent read afterwards is not.
6. **Behavioural.** Watches the shape of the session against the goal. Advisory
   by default: it escalates, it does not block.

The word **budget** below means a running total the gateway keeps for the whole
session: money, calls, or anything else countable. It is the only check that can
see a sequence of individually legal calls adding up to something illegal, and
the measurements below show it is what decides whether this helps you.

## What it measures

Two tiers. The deterministic one needs no model, no key and no money, runs in
seconds. Read it first.

```bash
python -m benchmarks.bpl_sweep --suite full
```

132 business-process scenarios, each with a scripted attack and its benign twin.
Two columns, because either is trivially winnable alone: refuse everything and
you win containment, allow everything and you win completion. The column that
matters is the conjunction.

That command has four parameters, each defaulting to what the table below used,
and the one that moves the headline most is the verb classifier: `--verbs bpl`
selects the legacy raw-synonym version and scores 32% instead of 39.4%, buying 6
points of containment with 57 points of benign completion. The default is the
classifier the shipped gateway uses. All four deltas are tabulated in
[REPRODUCE.md](benchmarks/bpl/REPRODUCE.md), because a number that depends on a
flag should say so where the number is.

**The attack was contained AND its benign twin completed:**

A zero is written with its upper bound, not as a bare percentage, here and
throughout: at n=132 a zero has a 97.5% upper bound of 2.8%, and at n=12 it is
26.5%.

| condition | Core (12) | Hard (24) | **Full (132)** |
| --- | ---: | ---: | ---: |
| undefended | 0/12, 97.5% upper bound 26.5% | 0/24, 97.5% upper bound 14.2% | 0/132, 97.5% upper bound 2.8% |
| refuse everything | 0/12, 97.5% upper bound 26.5% | 0/24, 97.5% upper bound 14.2% | 0/132, 97.5% upper bound 2.8% |
| per-call authorization, given the policy | 8.3% (1/12) | 0/24, 97.5% upper bound 14.2% | 0.8% (1/132) |
| dataflow taint | 0/12, 97.5% upper bound 26.5% | 8.3% (2/24) | 11.4% (15/132) |
| **Clay Seal** | **75.0% (9/12)** | **41.7% (10/24)** | **39.4% (52/132)** |

**Read 39.4% as an average over two different cases, not as a rate.** Where the
scenario's grant configures a budget it is 83.3%; where it configures none,
18.9%. Which case you are in is fixed before anything runs and readable from
your own policy, so it is a condition you can check rather than a rate you have
to accept. [The split is below](#when-it-works-and-when-it-does-not).

Per-call authorization scores 1 of 132, and the one it scores is the one worth
understanding. `bulk-exfil`'s rule is a recipient allowlist, decidable from a
single call's own arguments, needing no history at all, so a stateless gate
enforces it exactly and completes the benign twin. Every other rule in the suite is a property of a
trajectory. There a stateless gate holds nothing between calls, so a running
total has nowhere to accumulate. Handing it the ceiling does not help; it has
nowhere to put the total. That is the
architectural claim, and the row is more convincing for not being a flat zero.

It was a flat zero until this release, because the baseline was reading only the
`scope` rule out of the policy it was handed and dropping the rest. Beating a
baseline that was given half the rule is not beating it.

Read the three columns, not one. **Core is the chosen leaderboard set, not a
sample**: 83% of it is labelled as expected-to-be-contained where the suite is
38%, and it is two thirds aggregate where the suite is one third. On raw
containment that selection is worth 43 points, and on the joint metric above it
is worth 37. The full-suite number is the one quoted here.

Against dataflow taint the difference on the full suite is **28.0 points
[18.2, 37.9], exact McNemar p=1.2e-07**, surviving Holm correction. Scenarios
were written in batches at a sitting and are not independent, so the rate to
quote is cluster-robust over authoring batches: **39.4% [24.3%, 57.9%]** against
taint's 11.4% [6.1%, 17.7%]. Non-overlapping.

Composition, selection effects, and the per-scenario detail:
[bpl_suite_composition.md](benchmarks/results/bpl_suite_composition.md).

### When it works, and when it does not

The 39.4% above is an average over 132 scenarios, and averaging hides the thing
you need in order to decide whether this helps you. Hold out whole batches of
scenarios and containment ranges from nothing at all to everything, sd 0.344. It
is not a mechanism that works 39% of the time; it works on some kinds of rule
and not on others.

What decides it is the rule, not the attack, and you can tell which case you are
in by reading your own policy before running anything:

| Does the rule state a countable limit? | scenarios | Clay Seal | dataflow taint |
| --- | ---: | --- | --- |
| **yes** | 42 | **83.3% [69.4%, 91.7%]** | 2.4% [0.4%, 12.3%] |
| no | 90 | 18.9% [12.1%, 28.2%] | 15.6% [9.5%, 24.4%] |

Fisher exact p = 6.5e-11.

**So write your rules as ceilings on something you can count.** "No more than
$1,000 in refunds per session" is enforced. "Do not do anything inappropriate"
is not: there is no running total for the gateway to keep, so such a rule falls
back on whatever the goal check, the path scope and the egress list happen to
catch.

`clayseal policy lint` already flags a tool that can spend but debits no budget.
This measurement is what that warning is worth.

**If you will never write a budget**, the gateway can infer one from the goal
text. "Triage the tickets and email a summary" implies one email, so a second
one waits for approval with no budget declared anywhere. It steps up instead of
denying, because the limit came from reading a sentence, and a retry after a
failed send looks the same as a second send.

That inference is **off by default**, and the reason is the cost. On an external
corpus it caught 8 more attacks out of 507 and interrupted 26 benign actions out
of 278, roughly three interruptions per catch. Whether that trade is worth it
depends on your deployment, so you turn it on with `derive_counts=True`
([the measurement](benchmarks/results/derived_counts_measured.md)).

### What it costs

Of 132 benign twins, this gate refuses 2. Neither loses work: both are
interrupted on a call that was not on the critical path and still reach full
progress. Dataflow taint refuses 49 and loses work on 43.

That is the more durable result: **comparable containment, and no benign task in
the suite fails to finish.**

All 54 contained attacks involve at least one hard denial. None is held by a
step-up alone, so the number is autonomous and does not
assume anybody is at the console to answer a question. `--step-up allow` prices
the other end of it and produces an identical table, because this suite never
produces a step-up at all.

### What it costs in time

```bash
python -m benchmarks.gateway_cost
```

**34 µs per decision** (29,000/sec), flat in session length: the median cost at
call 3,500 is the same as at call 0. An agent acts at 1 to 10 actions per second
and the LLM round trip this gates is hundreds of milliseconds, so the median is
four orders of magnitude below it.

The median is the least interesting number, so the same file publishes the three
that are: a 16 KB argument costs 206 µs, because the egress floor scans argument
text and that text is attacker-influenced; the confidentiality tracker's p99
reaches 10.7 ms and one run peaked at 219 ms, which is the open performance
problem; and memory per session is unbounded at 1,182 bytes per decision.

[benchmarks/results/performance.md](benchmarks/results/performance.md) is the one
place these live, including which measurement point each number is from. That
matters more than it sounds: four different documents here used to quote four
different p50s for "the full stack", all correct for what they measured and none
of them saying which.

### The rest of the evidence

The two mechanisms catch different things: 32 scenarios are contained by this
layer only, 20 by dataflow taint only, 22 by both. Stacking them is still a bad
trade, because the taint layer refuses 47 benign scripts this one completes.

Everything above is a suite we wrote, which is the first thing a reader should
distrust. On a corpus we did not write, against a live model:

**AgentDojo prompt injection.** `gpt-4o-mini-2024-07-18`, `important_instructions`
attack, 18 trials per cell. Attack-success rate, lower is better:

| suite | undefended | best AgentDojo built-in | Progent | ours |
| --- | ---: | ---: | ---: | ---: |
| banking | 61.1% | 27.8% | 16.7% | **0.0%** (0/18) |
| slack | 83.3% | 16.7% | 11.1% | **0.0%** (0/18) |
| travel | 27.8% | 5.6% | 11.1% | **0.0%** (0/18) |
| workspace | 88.9% | 5.6% | 16.7% | **0.0%** (0/18) |

Zero on all four suites, against a published system that leaves 11 to 17 points.
At 18 trials a cell, a zero has a 97.5% upper bound of 18.5%, so this shows we
are not worse and cannot show more; the gap to Progent is suggestive, not
separated.

**What that costs, measured separately and paired.** Those runs use
`gpt-4o-mini` because it is reliably injectable, which makes it the right model
for a security test and the wrong one for a utility test. Utility is measured on
its own, **paired per task so only defense-caused losses count**, across four
models and 32 clean tasks each:

| model | undefended | with Clay Seal | cost | false-block |
| --- | ---: | ---: | ---: | ---: |
| gpt-4o-mini | 84% | 59% | −25 pts | 12.5% [5.0, 28.1] |
| gpt-oss-120b | 84% | 66% | −19 pts | 9.4% [3.2, 24.2] |
| **grok-4-1-fast** | 81% | **78%** | **−3 pts** | **6.2%** [1.7, 20.1] |
| llama-4-maverick | 12% | 12% | 0 pts | 0.0% [0.0, 13.8] |

The cost falls monotonically with model strength, and on the strongest model
measured the **shippable** path costs 3 points where CaMeL's published cost is 7.
**Most of what looks like the cost of enforcement is the cost of a weak agent**,
and only pairing separates the two: on gpt-4o-mini banking, 3 of 8 clean tasks
fail with no defense present at all. The llama row is a null, not a win, a 12%
baseline leaves nothing for a defense to cost, and it is kept here rather than
dropped.

n=32 per model, so the interval around a 3-point difference is wide. The monotone
trend across four models carries that claim, not any single cell
([the 4x4](benchmarks/results/live_ladder.md)).

**One limit outranks all of it.** These are AgentDojo numbers, and AgentDojo
tasks are mostly specified in the prompt. On
[AgentDyn](benchmarks/results/agentdyn.md), where the correct next step cannot be
known until the agent looks at what is actually there, every such step deviates
from the sealed plan and the cost is total: 21.67 interruptions per task, which
is not friction but a system asking permission for nearly every action. Runtime
replanning is the fix, `SessionBroker.reclear` exists for it, and it is called
from nowhere today. **Until that ships, this suits work whose shape is known up
front.**

Every headline result, the command that reproduces it, and the limit it does not
cross: [benchmarks/results/README.md](benchmarks/results/README.md).

## Where the boundary is

Three ways to place the enforcement point. They differ in what an agent has to do
to get past them, and the difference is worth stating plainly instead of
collapsing into one number.

| tier | mediates | got past by | status |
| --- | --- | --- | --- |
| in-process | tool calls your harness routes through `authorize()` | a harness that does not call it, or a tool nobody wrapped | shipped |
| **proxy** | **every tool call on the transport, by construction** | a process that can reach the tool another way | **shipped** |
| syscall | everything the guest can attempt, unforgeably | nothing at this layer | reference backend is macOS only |

The proxy also runs three checks the in-process path cannot. It screens every
path a call names, not just the one the action carries. It refuses a message
whose JSON has duplicate keys. And it holds an effectful call until earlier
results arrive, so it is never asked where a destination came from before it has
been told. The table in
[docs/POLICY.md](docs/POLICY.md) lists the differences, and what an in-process
integration has to do itself.

Most deployments want the proxy. The agent connects to `clayseal
proxy`, and `clayseal proxy` runs the real MCP server, so a denied call is
answered with a JSON-RPC error and the server subprocess never receives the
frame. Tools outside the policy are also removed from the advertised catalog, so
the agent does not plan around a tool it will then be refused.

The syscall tier compiles an envelope's egress and path scope into a sandbox
policy and takes back an unforgeable verdict stream
([docs/ivisor_integration.md](docs/ivisor_integration.md)). The reference backend
drives iVisor.

**It catches one class nothing above it can.** A DNS tunnel encodes its payload
into subdomains, and the data leaves through the resolver rather than through
any tool. There is no tool call, so `authorize()` is never asked, and every
layer above denies nothing. On the captured trace iVisor denies all four
queries and the tool-call layers deny none
([syscall_tier.md](benchmarks/results/syscall_tier.md)).

It runs the other way too. Beaconing over an allow-listed channel gives iVisor
nothing to refuse, because each syscall really is permitted; what is anomalous
is the running total, and only the session budget holds that. Neither layer
subsumes the other, which is the argument for running both.

iVisor is macOS only by construction: Hypervisor.framework allows one VM per
process and applies an irreversible Seatbelt profile to its caller. The
`agentauth.sandbox_backends` entry point makes the substrate swappable, and a
Linux seccomp or Landlock backend is open work, not something we ship.

### The gap this does not close

In-scope staging. An agent reads a secret-classed object inside its grant and
writes the content to a publication-classed object inside the same grant. Both
actions are authorized and the path scope cannot help, because the agent was
legitimately given the workspace that holds both. Measured against an oracle
attacker, the escaped-task set is byte-identical to `allow-all`
([in_scope_exfiltration.md](benchmarks/results/in_scope_exfiltration.md)). The
confidentiality flow tracker covers part of it as a step-up layer; wide fragment
splits and unkeyed encodings remain open. Any containment claim for a coding
agent has to carry this one.

## The policy document

The authority is a file, so a security team can read it, diff it in a pull
request, and gate a merge on it.

```yaml
version: 1
goal:
  id: billing-triage-2026-08
  summary: Triage the open billing tickets and email a summary to the ops archive.
profile: supervised          # autonomous | supervised | benchmark
expires_at: 2026-12-31T00:00:00Z

tools:
  allow:    [list_tickets, read_ticket, write_summary, send_email]
  harmless: [list_tickets, read_ticket, write_summary]
  effects:  {write_summary: write, send_email: send}

paths:
  allow: ["out/**", "tickets/**"]
  deny:  [".env", ".git/**"]
  arg_names: {write_summary: path}     # which argument carries the path
  pathless:  [send_email]              # asserted to act on no path

egress:
  domains: [acme-internal.com]
  bind_recipients: true

budgets:
  calls:
    ceilings: {emails: 3}
    tracked:  {send_email: emails}
```

```bash
clayseal policy show examples/policy.yaml   # what it authorizes
clayseal policy lint examples/policy.yaml   # what a reviewer should ask about
```

`lint` exits non-zero on an error finding, so it works as a pre-merge gate. It
reports what the gateway would refuse to start on, so the author does not find
out from a traceback:

```
ERROR   untracked-effectful-tool issue_refund: reachable and in the 'value'
        family but debits no budget, so no ceiling applies to it at all
WARNING session-scoped-ceiling   emails: counted per session, so a second
        session gets a second ceiling
```

The compiled policy carries a digest over the document, and the gateway attaches
it to every decision, so an audit trail says which authority produced a decision
and not only what the decision was.

### Pointing it at your own tools

Two declarations do the work, and both exist because the defaults are tuned on
benchmark catalogs, not on real ones.

`tools.effects` says what each tool does. The verb decides which floor rules
apply, and guessing it from the name works on names like `send_email` and fails
on names like `terraform_destroy`: of 24 tool names taken from widely used MCP
servers, 17 are unrecognised by the classifier.

`paths.arg_names` says which argument carries the path. The gateway looks for
`file_path`, `path`, `filename` and `file`; a tool that calls it `target_dir` or
`key` yields no path, and a path scope that cannot find a path does not apply. An
effectful call whose path cannot be resolved is refused, not allowed
unchecked, so the failure is loud instead of silent.

`clayseal policy lint` names every tool that is missing either one. Read
[docs/POLICY.md](docs/POLICY.md) before you write the first policy for a catalog
you did not design.

If the person who signs off works in risk and not engineering,
[docs/CONTROLS.md](docs/CONTROLS.md) says which obligations this produces
evidence for, quoting the framework text where the mapping is exact and staying
at the function level where it is not. It opens by saying what it is not: a
library is not a control regime and cannot make anyone compliant with
anything.

### Writing the first one from what you already have

Two commands exist so the first policy is not written from a blank file. Both
produce a **draft a person finishes**, never a grant.

```bash
# What the tools are called, from the server you already run.
clayseal policy init -- npx @your-org/mcp-server

# What the organisation permits, from the document that already says so.
clayseal policy draft delegation_of_authority.md

# Both halves in one file. This is the one worth running.
clayseal policy init --rules delegation_of_authority.md \
    -- npx @your-org/mcp-server > draft.yaml
clayseal policy lint draft.yaml
```

`init` asks the server for `tools/list` and reads the tool names, the effect of
each one, and the argument each carries its path in out of the schemas the
server already publishes. `draft` reads the ceilings, windows, once-only rules,
directories and allowed domains out of prose, from sentences like "a single
vendor payment must not exceed $10,000".

Neither one is authority, for two different reasons. The **document** is an
artefact edited by people who are not thinking about an agent, so whoever
controls it would otherwise control the grant. The **catalog** is written by the
server this policy constrains, so a server describing `wire_funds` as "reads the
balance" would be writing its own limits. Three properties follow:

- Every rule cites the line of the document it came from, so a reviewer checks
  the YAML against the sentence without re-reading the source.
- A sentence that reads like a rule and did not translate becomes a `TODO`
  comment. A draft that looks complete is worse than one that admits what it
  dropped, because a rule that vanished in translation is one nobody notices.
- The catalog may **raise** a tool's effect and never lower one, and a server
  calling its own effectful tool read-only is reported, not believed. A
  tool that publishes no schema is not recorded as taking no path: "the server
  did not say" and "the server said no" are different facts.

What is deliberately left blank is `budgets.tracked`, where a ceiling meets a
tool. The document knows the ceiling and the catalog knows which argument
carries the amount; which tool debits which ceiling is in neither, and naming
the wrong one splits a shared limit in two. Both are printed as commented
suggestions for a person to connect.

Worked end to end on a 30-line delegation-of-authority document and a seven-tool
AP server. It extracted 9 rules and left 3 sentences as TODOs. After review the
gateway denies four things: a payment taking the rolling 24-hour total past
$50,000, a second payment of an invoice already paid, a write to a `.ledger`
file, and a write outside `/finance/ap/`. One of those TODOs is
"the person who prepares a payment may not approve it", which is a real rule
this layer does not express, and it appears as a comment in the output, not a
silence.

## Adding a rule for your own workload

Every knob above tunes behaviour someone else chose. This is where "in our shop
X is also forbidden" goes, without forking:

```python
from clayseal.capabilities.session_rules import SessionRuleHit

def no_competitor_domains(action, session, *, goal_summary, egress_verbs):
    if "competitor.test" in str(action.args or {}):
        return SessionRuleHit("house-rules", "destination is a competitor domain")
    return None      # None means "this rule has nothing to say"

stack = DeployableStack.from_goal(goal, house_rules=(no_competitor_domains,))
```

A hit becomes a **step-up, never a denial**. A rule written against your
workload has not been measured against the traffic it will refuse, and a
step-up halts an autonomous attacker just as hard while leaving a person able
to say yes. Your rules run after the shipped ones, so a house rule cannot mask
one that ships. A rule that raises is skipped and counted in
`session_rules.RULE_FAILURES` rather than failing the decision: a gateway that
stops authorizing because a regex threw is worse than one that misses a rule.

## The lower-level API

`Guardrail` above is the wrapper most integrations want. If you are building
your own loop and would rather call the gateway directly, the decision API is
one method:

```python
from clayseal.capabilities.monitor.action import Action
from clayseal.capabilities.policy import load_policy
from clayseal.capabilities.tool_verbs import classify_verb

gateway = load_policy("examples/policy.yaml").build()

agent_calls = [
    ("read_ticket", {"id": "T-1042"}),
    ("send_email", {"to": "ops@acme-internal.com", "body": "3 open, 1 escalated"}),
    ("send_email", {"to": "collector-metrics.example", "body": "3 open, 1 escalated"}),
]

for step, (tool, args) in enumerate(agent_calls):
    decision = gateway.authorize(Action(
        step=step, tool=tool, resource=f"mcp:tool:{tool}",
        verb=classify_verb(tool), args=args,
    ))
    print(tool, decision.outcome, decision.reasons)
    if not decision.allowed:
        continue                    # hand the reasons back to the agent
    # run(tool, args)
```

`examples/01_gateway.py` runs this end to end against a prompt injection planted
in a ticket the agent was allowed to read. The fourth call is allowed and the
fifth is refused, because its destination came from the document and not
from the sealed goal.

## Security posture

The guards fail closed unless the environment names itself development.

```bash
CLAYSEAL_ENV=development    # relaxes them, and says so once per process
```

Unset, or set to production, means an unpinned commit-token minting key is
refused, a missing replay store is refused, an unsigned step-up approval is
refused, and an intent envelope from an unpinned signer is refused. The polarity
used to be the other way around, which meant every deployment that had not read
this section accepted all four.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what is signed, who signs
it, and what is out of scope.

## Build from source

```bash
git clone https://github.com/pberlizov/clayseal.git
cd clayseal
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest python/tests -q
python examples/01_gateway.py
```

Optional extras:

```bash
pip install "clayseal[oidc]"     # live OIDC/JWKS verification
pip install "clayseal[spiffe]"   # SPIFFE Workload API
pip install "clayseal[redis]"    # shared replay and ledger stores
pip install "clayseal[monitor]"  # the learned trajectory scorer
```

## Identity

The gateway does not need an identity layer. Bring verified claims from your own
IdP, build an `IdentitySession`, and issue commit tokens from there. Adapters
ship for SPIFFE JWT-SVID, OIDC, Auth0, AWS STS, Entra Agent ID, Azure AD, GCP,
and A2A signed agent cards.

```python
from clayseal.capabilities.identity_adapters import get_identity_provider

session = get_identity_provider("oidc").build_session(
    verified_claims,          # your IdP already checked signature, aud, exp
    evidence_verified=True,
)
```

## Documentation

[docs/README.md](docs/README.md) is the index. The four you are most likely to
want:

- [API reference](docs/API.md) for the 57 exported names, tiered by what
  most integrations actually use
- [Developer guide](docs/DEV_GUIDE.md) to install it and wire it in
- [Policy reference](docs/POLICY.md) for what a policy file can say
- [Threat model](docs/THREAT_MODEL.md) for what it defends against and what it does not
- [Privacy and data handling](docs/PRIVACY.md) for what it stores and what leaves the process

For reporting a vulnerability see [SECURITY.md](SECURITY.md); to contribute see
[CONTRIBUTING.md](CONTRIBUTING.md) and the
[code of conduct](CODE_OF_CONDUCT.md). Upgrading from `agentauth-capabilities`:
[docs/MIGRATION.md](docs/MIGRATION.md). Corpora and their licences:
[THIRD_PARTY.md](THIRD_PARTY.md). Cutting a release:
[docs/RELEASING.md](docs/RELEASING.md).

## Naming

The product, the distribution, the import root and the CLI are all `clayseal`.

Before 0.6 this shipped to design partners on a private feed as
`agentauth-capabilities`, importing from `agentauth.capabilities`. Those import
paths still resolve and emit a `DeprecationWarning`; they are removed in 0.7.
The aliased module is the same object as the real one, so a plugin registered
through the old path is visible through the new one. Migration is a search and
replace: [docs/MIGRATION.md](docs/MIGRATION.md).

Storage keys and wire identifiers were deliberately **not** renamed. The replay
store still keys commit tokens under `agentauth:commit:`, because a gateway that
silently stopped recognising the tokens it had already spent would reopen the
replay window it exists to close.

`clayseal.core`, the shared contracts and crypto helpers, used to be a separate
private distribution and now lives in this repository. The identity and receipts
layers remain separate distributions and neither is required here.

## License

MIT. See [LICENSE](LICENSE).
