# Clay Seal

<img src="docs/assets/clay-seal-logo.png" alt="Clay Seal logo" width="420">

**Every action the agent took was authorized. The sequence still broke the rule.**

That is the failure this enforces against. An agent with a legitimate goal and a
legitimate tool grant issues eleven refunds of $900 each against a $1,000
approval ceiling. Every call passes a per-call check, because every call is
individually within policy. Nothing that decides one call at a time can see it.

Clay Seal is a gateway that sits in front of the tools and decides each action
against the whole session: the grant, the running totals, where the arguments
came from, and what the agent has already done.

```bash
pip install agentauth-capabilities
clayseal proxy --policy policy.yaml -- npx @your-org/mcp-server
```

## What it measures

Two tiers. The deterministic one needs no model, no key and no money, runs in
seconds, and is the one to read first.

```bash
python -m benchmarks.bpl_sweep --suite full
```

132 business-process scenarios, each with a scripted attack and its benign twin.
Two columns, because either is trivially winnable alone: refuse everything and
you win containment, allow everything and you win completion. The column that
matters is the conjunction.

**The attack was contained AND its benign twin completed:**

A zero is written as its bound rather than as a bare percentage, here and
throughout: at n=132 a zero has a 97.5% upper bound of 2.8%, and at n=12 it is
26.5%.

| condition | Core (12) | Hard (24) | **Full (132)** |
| --- | ---: | ---: | ---: |
| undefended | 0/12, 97.5% upper bound 26.5% | 0/24, 97.5% upper bound 14.2% | 0/132, 97.5% upper bound 2.8% |
| refuse everything | 0/12, 97.5% upper bound 26.5% | 0/24, 97.5% upper bound 14.2% | 0/132, 97.5% upper bound 2.8% |
| per-call authorization, given the policy | 0/12, 97.5% upper bound 26.5% | 0/24, 97.5% upper bound 14.2% | 0/132, 97.5% upper bound 2.8% |
| dataflow taint | 0/12, 97.5% upper bound 26.5% | 8.3% (2/24) | 11.4% (15/132) |
| **Clay Seal** | **75.0% (9/12)** | **41.7% (10/24)** | **39.4% (52/132)** |

Per-call authorization scores nothing on any set. It holds no state between calls,
so an aggregate constraint has nothing to accumulate against, and handing it the
ceiling does not give it somewhere to put the running total. That is the
architectural claim and it is the one that survives every cut of the data.

Read the three columns, not one. **Core is the chosen leaderboard set, not a
sample**: 83% of it is labelled as expected-to-be-contained where the suite is
38%, and it is two thirds aggregate where the suite is one third. On raw
containment that selection is worth 43 points, and on the joint metric above it
is worth 37. The full-suite number is the honest one and it is the one quoted
here.

Against dataflow taint the difference on the full suite is **28.0 points
[17.4, 36.4], exact McNemar p=1.2e-07**, surviving Holm correction. Scenarios
were written in batches at a sitting and are not independent, so the rate to
quote is cluster-robust over authoring batches: **39.4% [24.3%, 57.9%]** against
taint's 11.4% [6.1%, 17.7%]. Non-overlapping.

Composition, selection effects, and the per-scenario detail:
[bpl_suite_composition.md](benchmarks/results/bpl_suite_composition.md).

### When it works, and when it does not

A pooled rate hides the thing you need in order to decide whether this helps
you. Holding out whole authoring batches, containment ranges from nothing to
87.5%, sd 0.327. This is not a mechanism with a 38% success rate; it works on
some kinds of constraint and not on others.

The split that explains most of it is a property of the grant, not of the
attack, and it is readable from source before anything runs:

| the grant | n | Clay Seal | dataflow taint |
| --- | ---: | --- | --- |
| **expresses the constraint as a budget** | 42 | **83.3% [69.4%, 91.7%]** | 2.4% [0.4%, 12.3%] |
| does not | 90 | 18.9% [12.1%, 28.2%] | 15.6% [9.5%, 24.4%] |

Fisher exact p = 6.5e-11. So the deployment rule is the finding:

**Write the constraint as a ceiling on something countable or summable and it is
enforced. Where you cannot, the aggregate rung has nothing to accumulate
against, and you get whatever the envelope, the path scope and the egress list
happen to catch.**

`clayseal policy lint` already reports an effectful tool that debits no budget as
an error. This measures what that error is worth.

**And for the deployments that will never write one**, the gateway derives a
bound from the sealed goal. "Triage the tickets and email a summary" accounts for
one send; a second is held for approval, with no budget declared anywhere. It
steps up rather than denying, because the bound came from reading a sentence and
a retry looks identical to a second send.

Measured on an external corpus it contains 8 more attack events of 507 and
interrupts 26 benign actions of 278, about three interruptions per catch, all of
them step-ups rather than refusals. That is a deployment decision rather than a
free win, so the numbers travel with it
([derived_counts_measured.md](benchmarks/results/derived_counts_measured.md)) and
`derive_counts=False` turns it off. An optional inferrer fills the goals a
sentence does not state, runs once at seal time on trusted text, and can never
raise a bound the text supports. See [docs/POLICY.md](docs/POLICY.md).

Two shapes of ceiling exist because most written rules are one of them:

```yaml
budgets:
  value:
    ceilings: {refunds: "5000.00"}
    windows:  {refunds: 86400}        # rolling 24h, not per session
    tracked:
      issue_refund: {arg: amount, budget: refunds, identity: [invoice]}
```

`windows` makes the ceiling apply over a rolling period rather than for the life
of the gateway, and `identity` makes the effect once-per-object, so "pay each
invoice once, under ceiling" is expressible as the two constraints it actually
is. A ceiling can also be **conditional**, because real authorities are not
constants:

```yaml
    when:
      - if: {rush: true}
        ceilings: {refunds: "1000.00"}     # a guard may only TIGHTEN
```

A guard above the base ceiling is refused at compile time, and that is the
security argument rather than caution: conditions arrive as tool output, so a
guard that could raise a ceiling would let injected content widen a grant.
Raising authority is what a signed step-up is for. Facts come only from
structured fields, never from prose. Both were added after inspecting the residual, and
[grant_changes_2026_08.md](benchmarks/results/grant_changes_2026_08.md) discloses
what changing two scenario grants to use them moved, and how to subtract it.

Both analyses read no scenario labels at all, which matters because the suite's
own labels predict its outcomes with 97.7% accuracy and cannot be used to
evaluate anything. See [bpl_label_free.md](benchmarks/results/bpl_label_free.md)
and, for what the evaluation still cannot show,
[publication_readiness.md](benchmarks/results/publication_readiness.md).

### What it costs

Of 132 benign twins, this gate refuses 3. One loses work; two are interrupted on
a call that was not on the critical path and still reach full progress. Dataflow
taint refuses 49 and loses work on 43.

That is the tuning result, and it is more durable than the containment one:
**comparable containment at a thirtieth of the work lost.**

### The finding worth more than the ranking

The two mechanisms are not measuring the same thing. 32 scenarios are contained
by this layer only, 21 by dataflow taint only, 21 by both. Their union is 74 of
132, well above either alone.

Stacking them would still be a bad trade. On the joint metric the stack scores
31%, **down** from 38%, because the taint layer refuses 46 benign scripts this one
completes. The 21 it catches and we do not are a real coverage gap, and the way
to close it is at this layer's precision rather than by adding that layer's
recall.

### Live tier

`bpl_shared_policy.md` runs the Core twelve against `gpt-5-mini`, n=20 per cell,
every condition handed the same declarative rule, and records 0 violations in 240
runs against 55.0% for per-call enforcement. Read it with the qualifications it
carries: a zero at n=20 has a 95% Wilson upper bound of 16.1%, three of the twelve
scenarios do not discriminate because the undefended model complies on its own,
and progress is scored against policy-optimal rather than undefended progress.
And read it as the Core set, which is what the table above says that is worth.

On prompt injection, which is a more crowded problem, the deployable path holds
attack success to 0 of 18 on all four AgentDojo suites against Progent's 11 to
17%, and pays for it in clean utility on two suites
([head_to_head_injection.md](benchmarks/results/head_to_head_injection.md)). At
n=18 a zero has an upper bound of 18.5%, so that table shows we are not worse and
cannot show more.

## Where the boundary is

Three ways to place the enforcement point. They differ in what an agent has to do
to get past them, and the difference is worth stating plainly rather than
collapsing into one number.

| tier | mediates | got past by | status |
| --- | --- | --- | --- |
| in-process | tool calls your harness routes through `authorize()` | a harness that does not call it, or a tool nobody wrapped | shipped |
| **proxy** | **every tool call on the transport, by construction** | a process that can reach the tool another way | **shipped** |
| syscall | everything the guest can attempt, unforgeably | nothing at this layer | reference backend is macOS only |

The proxy also runs checks the in-process path cannot: it screens every path a
call names rather than the one the action carries, refuses a message whose JSON
has duplicate keys, and holds an effectful call until earlier results have
arrived so the provenance tier is not asked about a destination before it has
been told where the destination came from. The table in
[docs/POLICY.md](docs/POLICY.md) lists the differences, and what an in-process
integration has to do itself.

The proxy is the one most deployments want. The agent connects to `clayseal
proxy`, and `clayseal proxy` runs the real MCP server, so a denied call is
answered with a JSON-RPC error and the server subprocess never receives the
frame. Tools outside the policy are also removed from the advertised catalog, so
the agent does not plan around a tool it will then be refused.

The syscall tier compiles an envelope's egress and path scope into a sandbox
policy and takes back an unforgeable verdict stream
([docs/ivisor_integration.md](docs/ivisor_integration.md)). The reference backend
drives iVisor, which is macOS only by construction: Hypervisor.framework allows
one VM per process and applies an irreversible Seatbelt profile to its caller.
The `agentauth.sandbox_backends` entry point makes the substrate swappable, and a
Linux seccomp or Landlock backend is open work rather than something we ship.

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
reports what the gateway would refuse to start on, instead of leaving the author
to discover it from a traceback:

```
ERROR   untracked-effectful-tool issue_refund: reachable and in the 'value'
        family but debits no budget, so no ceiling applies to it at all
WARNING session-scoped-ceiling   emails: counted per session, so a second
        session gets a second ceiling
```

The compiled policy carries a digest over the document, and the gateway attaches
it to every decision, so an audit trail says which authority produced a decision
rather than only what the decision was.

### Pointing it at your own tools

Two declarations do the work, and both exist because the defaults are tuned on
benchmark catalogs rather than on real ones.

`tools.effects` says what each tool does. The verb decides which floor rules
apply, and guessing it from the name works on names like `send_email` and fails
on names like `terraform_destroy`: of 24 tool names taken from widely used MCP
servers, 17 are unrecognised by the classifier.

`paths.arg_names` says which argument carries the path. The gateway looks for
`file_path`, `path`, `filename` and `file`; a tool that calls it `target_dir` or
`key` yields no path, and a path scope that cannot find a path does not apply. An
effectful call whose path cannot be resolved is refused rather than allowed
unchecked, so the failure is loud instead of silent.

`clayseal policy lint` names every tool that is missing either one. Read
[docs/POLICY.md](docs/POLICY.md) before you write the first policy for a catalog
you did not design.

If the person who signs off is a risk function rather than an engineer,
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

# Both halves in one file, which is the one worth running.
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
  calling its own effectful tool read-only is reported rather than believed. A
  tool that publishes no schema is not recorded as taking no path: "the server
  did not say" and "the server said no" are different facts.

What is deliberately left blank is `budgets.tracked`, where a ceiling meets a
tool. The document knows the ceiling and the catalog knows which argument
carries the amount; which tool debits which ceiling is in neither, and naming
the wrong one splits a shared limit in two. Both are printed as commented
suggestions for a person to connect.

Worked end to end on a 30-line delegation-of-authority document and a seven-tool
AP server: 9 rules extracted, 3 sentences left as TODOs, and after review the
gateway denies the payment that would take a rolling 24-hour total past
$50,000, the second payment of an invoice already paid, a write to a `.ledger`
file, and a write outside `/finance/ap/`. One of those TODOs is
"the person who prepares a payment may not approve it", which is a real rule
this layer does not express, and it is a comment in the output rather than a
silence.

## In Python

```python
from agentauth.capabilities.monitor.action import Action
from agentauth.capabilities.policy import load_policy
from agentauth.capabilities.tool_verbs import classify_verb

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
fifth is refused, because its destination came from the document rather than
from the sealed goal.

## What the gateway checks, in order

Cheap and hard first, expensive and soft last. A floor denial never reaches the
behavioural layer.

1. **Floor.** Grant expiry, delegation depth, tool and capability grant,
   protected zones, path and resource scope, commit-token argument binding,
   egress destinations, budget reservation.
2. **Declaration.** When the agent declares a plan, the plan is checked against
   the sealed goal before any of it runs.
3. **Content.** Plan entailment and per-write content checks on consequential
   writes, as a step-up rather than a denial.
4. **Session state.** Running totals, taints, and the rules pack that reads them.
5. **Provenance.** Where a destination argument came from: the sealed goal, a
   structured field of a trusted read, or free text that arrived after the seal.
6. **Behavioural.** A goal-conditioned trajectory detector, advisory by default,
   which escalates rather than blocks.

Hard denial requires positive evidence. A scope miss steps up instead, because a
step-up halts an autonomous attacker just as hard and does not halt a legitimate
agent permanently.

## Security posture

The guards fail closed unless the environment names itself development.

```bash
AGENTAUTH_ENV=development    # relaxes them, and says so once per process
```

Unset, or set to production, means an unpinned commit-token minting key is
refused, a missing replay store is refused, an unsigned step-up approval is
refused, and an intent envelope from an unpinned signer is refused. The polarity
used to be the other way around, which meant every deployment that had not read
this section accepted all four.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what is signed, who signs
it, and what is out of scope.

## Install

```bash
pip install agentauth-capabilities
```

Two runtime dependencies, `cryptography` and `pyyaml`. From a checkout:

```bash
git clone https://github.com/pberlizov/clay-seal-capabilities.git
cd clay-seal-capabilities
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest python/tests -q
python examples/01_gateway.py
```

Optional extras:

```bash
pip install "agentauth-capabilities[oidc]"     # live OIDC/JWKS verification
pip install "agentauth-capabilities[spiffe]"   # SPIFFE Workload API
pip install "agentauth-capabilities[redis]"    # shared replay and ledger stores
pip install "agentauth-capabilities[monitor]"  # the learned trajectory scorer
```

## Identity

The gateway does not need an identity layer. Bring verified claims from your own
IdP, build an `IdentitySession`, and issue commit tokens from there. Adapters
ship for SPIFFE JWT-SVID, OIDC, Auth0, AWS STS, Entra Agent ID, Azure AD, GCP,
and A2A signed agent cards.

```python
from agentauth.capabilities.identity_adapters import get_identity_provider

session = get_identity_provider("oidc").build_session(
    verified_claims,          # your IdP already checked signature, aud, exp
    evidence_verified=True,
)
```

## Documentation

- [Developer guide](docs/DEV_GUIDE.md)
- [Threat model and key management](docs/THREAT_MODEL.md)
- [Policy reference](docs/POLICY.md)
- [Syscall-level enforcement](docs/ivisor_integration.md)
- [Privacy and data handling](docs/PRIVACY.md)
- [Security disclosure](SECURITY.md), [contributing](CONTRIBUTING.md)
- [Benchmark methodology and results](benchmarks/README.md)

## Naming

The product is Clay Seal. The distribution is still published as
`agentauth-capabilities` and imports from `agentauth.capabilities`, so existing
integrations keep working. The `clayseal` command is the CLI for both.

`agentauth.core`, the shared contracts and crypto helpers, used to be a separate
private distribution and now lives in this repository. The identity and receipts
layers remain separate distributions and neither is required here.

## License

MIT. See [LICENSE](LICENSE).
