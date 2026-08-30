# Evidence

Every measured claim, the command that reproduces it, and the limit it does not
cross. The README carries the headline and the one condition that decides
whether this helps you; this is the rest of it.

Nothing here needs a key or a network except the two sections that say they use
a live model.

- [What it measures](#what-it-measures), the 132-scenario deterministic suite
- [When it works, and when it does not](#when-it-works-and-when-it-does-not)
- [What it costs](#what-it-costs) in refused benign work
- [What it costs in time](#what-it-costs-in-time)
- [The rest of the evidence](#the-rest-of-the-evidence): eleven external corpora,
  a live model, and the one limit that outranks all of it

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
[REPRODUCE.md](../benchmarks/bpl/REPRODUCE.md), because a number that depends on a
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
your own policy, so it is a condition you can check and not a rate you have to
accept. [The split is below](#when-it-works-and-when-it-does-not).

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
[bpl_suite_composition.md](../benchmarks/results/bpl_suite_composition.md).

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
([the measurement](../benchmarks/results/derived_counts_measured.md)).

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

[benchmarks/results/performance.md](../benchmarks/results/performance.md) is the one
place these live, including which measurement point each number is from. That
matters more than it sounds: four different documents here used to quote four
different p50s for "the full stack", all correct for what they measured and none
of them saying which.

### The rest of the evidence

The two mechanisms catch different things: 32 scenarios are contained by this
layer only, 20 by dataflow taint only, 22 by both. Stacking them is still a bad
trade, because the taint layer refuses 47 benign scripts this one completes.

Everything above is a suite we wrote, which is the first thing to distrust. The
deterministic tiers replay **eleven external corpora** nobody here authored:

```bash
benchmarks/fetch_corpora.sh          # the corpora are not vendored; ~4 MB
python -m benchmarks.scoreboard
```

| corpus | contained | benign refused, complete grant | benign refused, half grant | n (attack / benign) | harm is defined by |
| --- | ---: | ---: | ---: | ---: | --- |
| redcode | 99.9% | 0.00% | not run | 718 / 344 | a path outside the workspace |
| ipi_coding | 100.0% | 0.00% | not run | 50 / 45 | an out-of-scope target |
| mcp_attack | 100.0% | 0.00% | **44.4%** | 5 / 9 | a poisoned tool or a mutated argument |
| agent_threat_bench | 100.0% | 0.00% | not run | 6 / 24 | a destination |
| advbench_agent | 100.0% | 0.00% | **45.5%** | 6 / 11 | a target |
| mind2web_sc | 98.0% | 1.00% | not run | 100 / 100 | a safety-critical step |
| b3 | 66.7% | n/a | not run | 9 / 8 | mixed |
| **agentharm** | **55.3%** | 0.00% | **55.6%** | 696 / 729 | **the content of an allowed action** |
| **sleight** | **31.0%** | n/a | not run | 129 / 311 | **the content of an allowed action** |

**The third column is the one to read, and it is why the second is not a
headline.** On six of these corpora the grant handed to the gateway is the
benign side restated, so a 0.00% refusal rate is true by construction and says
nothing: the policy was written from the answer. The third column rebuilds the
grant from half the benign events and scores it on the other half, which is what
an incomplete policy costs. Across every corpus where it is measured, including
the benign-only ones not listed here, it runs from 18.0% on `bfcl` to 55.6% on
`agentharm`. It is measured at the ladder floor and not on the full stack,
and where it says "not run" the number is unknown, not zero.

That is the same failure [AgentDyn](../benchmarks/results/agentdyn.md) measures
against a live model, and `grant_is_observed=True` closes its deterministic form
([observed_grant.md](../benchmarks/results/observed_grant.md)) on `tau2`. It has not
been re-run across the corpora above, so those are the pre-fix figures and they
stand until someone runs them. Where a **person** wrote the tool list rather
than a recording producing it, neither the cost nor the fix applies: the list is
an authorization, not a transcript.

**Two further corpora, ASB (2,040 attacks) and InjecAgent (1,598), score 100% and
are left out of that table instead of counted.** Every attack in them uses a
tool the grant never issued, so a trivial baseline scores the same. A number a
naive rung also earns is not evidence about this system, and reporting it would
add 3,638 attacks to the numerator for nothing.

**The spread is the finding, and it is not noise.** It is the same line the
132-scenario suite draws with budgets: where harm is defined by something the
gateway can *bind to*, containment is 98 to 100%; where harm is defined by the
meaning of an otherwise authorized action, it falls to 31 to 55%. This is an
authorization layer, not a harm classifier, and
[THREAT_MODEL.md](THREAT_MODEL.md) declares content-defined harm out of
scope for exactly that reason.

Containment at whatever false-block rate an engine picked for itself is not a
headline, and this repo's own review rules forbid quoting it as one. At a
**fixed 1% benign-block rate**, with a deny-all control that must score zero:

| corpus | scorer | detection @1% FPR | AUC |
| --- | --- | ---: | ---: |
| redcode | deny-all control | 0.0% | 0.500 |
| redcode | `ngram`, the shipped detector | 0.0% | 0.425 |
| redcode | `target`, **not wired into the gateway** | 100.0% | 1.000 |
| ipi_coding | `target`, not wired | 100.0% | 1.000 |
| agentharm | `target`, not wired | not reached | 0.628 |
| sleight | `target`, not wired | not reached | 0.511 |

Read the second and third rows together. The behavioural channel that separates
these corpora cleanly is a **research scorer that the shipped gateway does not
run**; the detector it does run scores 0.0% here, at an AUC below chance. That
gap is tracked in
[docs/INTEGRATION.md](INTEGRATION.md) and it is the honest reason the
containment table above rests on the floor and content tiers, and not on
behaviour. On the content-defined corpora even the research scorer is at chance
([opeval.md](../benchmarks/results/opeval.md), five seeds).

**Against a live model.** AgentDojo prompt injection, `gpt-4o-mini`,
`important_instructions`, deployable configuration, **three sweeps per suite**:

| suite | undefended ASR | defended ASR | runs |
| --- | ---: | ---: | ---: |
| banking | 66.7% | 0.0% | 0 / 54 |
| slack | 81.5% | 0.0% | 0 / 54 |
| travel | 38.9% | 1.9% | 1 / 54 |
| workspace | 88.9% | 0.0% | 0 / 54 |

**Pooled: 1 attack success in 216 runs, 0.5% [0.1, 2.6]**
([head_to_head_injection.md](../benchmarks/results/head_to_head_injection.md)). Progent, the closest
published comparable, leaves 11.1 to 16.7% on the same suites and attack, though
its figure is a single 18-run sweep. Our own single sweeps were the same size
until this run, and 0 of 18 justifies nothing tighter than [0, 17.6%], which is
why the pooled number is the one quoted.

**What that costs, measured separately and paired.** `gpt-4o-mini` is used above
because it is reliably injectable, which makes it right for a security test and
wrong for a utility test. Utility is measured on its own, **paired per task so
only defense-caused losses count**, across four models and 32 clean tasks each:

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
fail with no defense present. The llama row is a null, not a win, a 12% baseline
leaves nothing for a defense to cost, and it is kept.

n=32 per model, so the interval around a 3-point difference is wide. The monotone
trend across four models carries that claim, not any single cell
([the 4x4](../benchmarks/results/live_ladder.md)).

**One limit outranks all of it.** Every number above comes from corpora whose
tasks are mostly specified in the prompt. On
[AgentDyn](../benchmarks/results/agentdyn.md), where the correct next step cannot be
known until the agent looks at what is actually there, every such step deviates
from the sealed plan and the cost is total: 21.67 interruptions per task, which
is not friction but a system asking permission for nearly every action.

**The deterministic form of that failure is now closed.** A grant derived from
observed traffic enumerates the tools a recording happened to contain, so every
tool it missed is refused even where the same mandate already authorizes that
verb class. Measured on held-out mandates across **8,849 benign events in five
corpora**, the shipped default refuses between 27% and 56% of them:

| | tau2 | toolemu | atif | asb | agentharm |
| --- | ---: | ---: | ---: | ---: | ---: |
| shipped default | 45.00% | 54.74% | 26.95% | 50.00% | 55.56% |
| `grant_is_observed` | **0/7177** | **0/559** | **0/282** | **0/102** | 8.37% |

Containment is unchanged on every attack corpus where the mechanism actually
fired ([observed_grant.md](../benchmarks/results/observed_grant.md)). It is off by
default and must stay off wherever a human wrote the tool list, because there
the list is an authorization, not a transcript.

That is the same mechanism AgentDyn punishes, measured on replayed traffic
and not against a live model. **AgentDyn itself has not been re-run**, so
the 21.67 stands as the published figure until someone does.

Every headline result, the command that reproduces it, and the limit it does not
cross: [benchmarks/results/README.md](../benchmarks/results/README.md).

### The attacker every number above assumes

Everything above replays a fixed attack, written without knowledge of this
gateway. That is the standard the whole field is measured against, and it is a
known weakness of the whole field. The same method made in-band defenses look
strong until defense-aware attacks broke twelve of them at over 90% success
([arXiv:2606.26479](https://arxiv.org/abs/2606.26479), which places CaMeL,
FIDES, Progent, RTBAS and FORGE in one family and says an optimized white-box
attack against any of them is still open).

So there is an attacker here that knows the defense. It sees each verdict,
mutates the attack that failed, and searches again.

```bash
python -m benchmarks.adaptive --sweep --limit 20 --rounds 3
```

Ten seconds, no key. 24 corpus and objective pairs, 173,699 attack candidates.
In 23 of the 24, going from a blind attacker to one with full visibility of the
verdicts changes containment by nothing at all. More search budget does not
help either: on redcode exfiltration, 12,200 candidates and 87,080 candidates
both give 100%.

The exception is the useful part. On `agentharm` persistence a blind attacker
is contained 20% of the time and an attacker who can see the verdicts is
contained never, so adaptivity is worth 20 points there. It is the one place
measured here where knowing the defense helps.

Full grid, the benign cost beside it, and the two cells where the control
scores as well as the gateway does:
[adaptive_deterministic.md](../benchmarks/results/adaptive_deterministic.md).

**The live half is still open.** An attacker who talks a real model into the
action is a different question, and the file that measures it is stamped
`unverified` because no command was recorded for it. Nothing from it is quoted
here.

A ceiling is arithmetic. It does not care how the eleventh refund was worded,
which is why the countable-limit rules are the ones that hold up, and it is the
same line the 83.3% and 18.9% split draws.
