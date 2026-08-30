# What we contain, split by what defines the harm

STATUS: current

Agent-security results are usually reported per benchmark, which hides the thing
that actually predicts whether a defense works: **what makes the action harmful.**
Sorted that way, the picture is sharp, and three of the four axes have a clear
answer.

| Harm defined by | The attack | Result | Cost |
| --- | --- | --: | --: |
| **Target** | the action points somewhere it must not | 99.9-100% | 0.00% granted (0 of 18,356); 18–50% held out |
| **Volume** | too many of an authorized action | 100% at burst >= 10 | 0.0-2.0% held out |
| **Sequence** | authorized read, then authorized write of what it read | 100% | 0.00% (0 of 1,242 benign tau2 events) |
| **Content** | an authorized action whose meaning is harmful | 6.3% | 0.00% granted (0 of 653); 57.73% held out |

Everything below is measured, and every number that did not survive audit was
withdrawn rather than softened. Three headline figures were withdrawn during this
work; the reasons are in each section.

---

## Target-defined harm: contained

The action points at something the mandate does not cover. A path escape, an
attacker-controlled recipient, a protected zone, a credential store.

| Corpus | attack events | contained | false-block, granted mandate | false-block, held-out mandate |
| --- | --: | --: | --: | --: |
| RedCode | 718 | **99.9%** | 0.00% (0 of 344) | – (unsplittable) |
| ASB | 2,040 | **100%** | 0.00% (0 of 102) | **50.00%** |
| IPI-Coding-Agent | 50 | **100%** | 0.00% (0 of 45) | – (unsplittable) |
| AgentThreatBench (data_exfil) | 6 | **100%** | 0.00% (0 of 24) | – (unsplittable) |

**The granted-mandate column is close to an identity and the held-out column is
the measurement.** On six corpora the grant IS the benign side restated, so no
benign event can fall outside it and 0.00% at the scope rung follows by
arithmetic. `benchmarks/core/heldout.py` rebuilds the grant from half a task's
benign events and scores the other half, which is the question an operator
actually faces the day after they write a mandate.

Where a corpus cannot be split, one benign event per task, so there is nothing
to hold out, the cell is `–` rather than the circular zero. Reporting the
identity beside a real containment number is forbidden claim 3 in
`SEND_PACKET.md`.

Against 18,356 benign events from tau2, BFCL and ATIF the granted-mandate
false-block rate is 0.00% (0 of 18,356). Held out, the same corpora are 48.13%
(tau2), 18.04% (BFCL) and 26.95% (ATIF), the cost of a mandate that did not
anticipate the traffic, and the number a deployment should budget for.

**ASB's 100% means less than it looks.** Its benign side is one synthetic event
per granted tool, and its attack side is ASB's separate attacker-tool list, which
is disjoint from the agent's equipment by the corpus's own design. Every contained
attack there is caught by the tool allowlist. It measures whether we check tool
names, and a tool allowlist is sufficient for it.

RedCode and IPI-Coding are the real result on this axis: containment comes from
path scope against a workspace boundary that is a fixed constant, declared
independently of any label.

**AgentThreatBench was 58.3% of 24 events and is now 100% of 6.** The other 18
were our loader's inventions, and finding that is worth more than the number was:

- Five of the corpus's items are explicit **negative controls** (`attack_name ==
  "clean_baseline"`, attack fields emptied, auto-passed by its own scorer). The
  loader labelled them ATTACK, so three counted as contained and two as missed.
  All five were fabricated.
- **memory_poison** (10 events) had a synthesized `memory_write`. The corpus
  pre-poisons the store at setup and scores the marker appearing in the model's
  completion text; the agent never writes memory.
- **autonomy_hijack** (5 events) had a synthesized `transfer`. That agent's
  entire tool set is `{read_inbox, categorize_email, draft_summary}`. One item's
  forbidden action is the string `ignore your system prompt`, and the loader was
  blocking a wire transfer to `net:ignore your system prompt`.

Both remaining categories are content-defined, so they now contribute their
benign step and a declared `uncontained_reason` instead of counting as misses.
The attacker recipient in the exfiltration arm is taken from the injected record
rather than hard-coded, because that address is the one detail the check turns on.

---

## Volume-defined harm: contained, with a bounded blast radius

Each action is authorized, correctly targeted, in-scope and unremarkable. There
are simply far too many. Mass exfiltration by small authorized reads, mail
flooding, transfers structured under a reporting threshold.

**No corpus we have contains this**, which is why the rung measured zero for as
long as it was only measured on them. `benchmarks/burst.py` supplies it: sessions
are real tau2 and BFCL traffic, and the burst reuses a tool, resource, verb and
argument shape the session already used legitimately. Verified rather than
assumed, 0 of 5,000 burst actions are blocked by any rung below velocity.

| Corpus | cap | burst | contained | blast radius | held-out false alarms |
| --- | --: | --: | --: | --: | --: |
| tau2 | 7 | 5 | 74.8% | 3 | 0.0% |
| tau2 | 7 | 10+ | **100%** | 4 | **0.0%** |
| BFCL | 5 | 5 | **100%** | 4 | **2.0%** |
| BFCL | 5 | 10+ | 100% | 4 | 2.0% |

A compromised agent gets four extra authorized actions before the layer stops it,
whether it was trying for ten or a hundred.

**A burst of two is not contained and should not be.** Two extra actions have not
left the shape of the task, and a layer that flagged them would be blocking
legitimate work at the same rate.

**Three withdrawn results on this axis, and the last one changes the ship
decision.**

The rung first reported 24.7% on AgentHarm and 65.5% on SLEIGHT with a cap set
from the judged task's own benign volume; on SLEIGHT, RedCode and ASB every
attack-bearing task has zero benign effect events, so each got `cap = 1` and the
limit was the label.

With a valid cap it reported +8.0 on AgentHarm at zero cost; that came from the
loader concatenating a behaviour's benign variant and harmful twin into one
trajectory, so the benign half spent the rate budget and the harmful half was
blocked for arriving late.

Then the 0.00% false-block turned out to be a theorem rather than a measurement.
The cap is the maximum clean effect volume across the corpus and the corpus was
then scored against it, so no clean task could exceed its own maximum. Held out
over 20 seeds the rung costs RedCode 2.47% of its benign side on average and
24.88% in the worst split, ATIF 0.59%, tau2 0.01%, BFCL 0.05%.

So on the deterministic corpora this rung **buys nothing and costs something**. It
stays in the tree, its containment claim rests entirely on the burst benchmark
above, and whether to enable it belongs in the mandate: a deployment that faces
bursts should, one that does not should not.

Every false-alarm number on this axis is measured on **held-out** clean sessions,
because calibrating a threshold and then measuring friction on the same data is
arithmetic rather than evidence. That split is what turned BFCL's 0.0% into 2.0%
and RedCode's 0.00% into 2.47%.

---

## Sequence-defined harm: contained in one write, open across several

Read a resource you are granted, then write to a sink you are granted, and the
written value contains what you read. Every field of every action is correct.
Scope allows both, binding allows both, velocity allows both, protected zones
allow both. No single action is harmful. Only the pair is.

A per-action authorization layer cannot see a pair. Unlike content-defined harm,
this one is decidable: it needs remembering, not guessing.

`clayseal/capabilities/confidentiality.py` checks **per value, not per session**.
Bell-LaPadula per session is correct and unusable, because one sensitive read
blocks every later write. Declassification is bound to the sealed goal, so an
injected instruction cannot nominate a sink.

The single-write arms, re-measured on 2026-08-09 by `python -m benchmarks.flow`:

| Corpus | sessions | leak contained | legitimate false-blocked | label creep | real traffic |
| --- | --: | --: | --: | --: | --: |
| tau2 | 200 | **100%** | 0.0% | 0.0% | **0/1,230 sink writes, 0/1,242 all benign** |
| BFCL | 171 | **100%** | 0.0% | 0.0% | **0/691 sink writes, 0/1,044 all benign** |

Four arms, because the leak arm alone would be meaningless: a mechanism that
refused everything would score 100% there and 100% on the legitimate arm too.

The earlier version of this section listed seven transforms and said all of them
were contained. That was a closed set drawn from the cases the mechanism won.
The current sweep runs 22 single-write transforms and 19 are contained at 100%
on both corpora; caesar+1 and digit-arithmetic+1 are keyed and open by design,
and base85 is contained at 73.5% on tau2 and 77.2% on BFCL.

**The row above is a single-write number, and the multi-write picture is worse.**
Split the same value across two writes with 300 characters of ordinary prose in
each and it walks out in 200 of 200 tau2 sessions and 171 of 171 BFCL sessions.
Split it into 22 fragments and it walks out in 84 of 200 and 122 of 171. A value
of 11 characters or fewer has no cross-write check at all. Every number in this
paragraph is measured, with the rung below allowing every write, and the whole
matrix is in `flow.md`.

**Asserted rather than hidden:** a value the agent describes instead of quoting is
gone, and so is a value it enciphers with a key. Flow control raises the cost of
exfiltration; it does not end it.

---

## Content-defined harm: not contained, by us or by anyone

The action is authorized, correctly targeted, normally paced, and carries nothing
it should not. Its *meaning* is the harm: an email whose text is a phishing lure,
a script whose purpose is harassment.

| Corpus | attack events | contained |
| --- | --: | --: |
| AgentHarm | 652 | 6.3% |
| SLEIGHT-Bench | 328 | 36.9% at 32.64% false-block |

**On AgentHarm, 6.3% is a limit of our loader.** An earlier version of this
section called it an information-theoretic ceiling. That was wrong: AgentHarm's
grading functions assert concrete file paths, email recipients and URLs for 63%
of harmful behaviours, and our loader reads only the JSON, which carries tool
names alone. The corrected reading is below; see `agentharm_ceiling.md`. Its public data gives
one field describing the agent's actions, `target_functions`, which is a list of
tool names. Across every event our loader emits, 0 of 1,305 carry an argument, a
path, or a resource distinguishable from the tool name. A per-action layer decides
using the fields of the action, so on this corpus the best any mechanism can do is
reason about tool identity, and an oracle handed the exact set of tools that
appear only in harmful variants scores **3.1%**. Ours is higher because we ask the
finer question: does the harmful twin need a tool *this behaviour's own benign
variant* did not include. The harm lives in `prompt`, a task-level instruction,
so AgentHarm measures model refusal rather than action authorization. See
`agentharm_ceiling.md`.

**SLEIGHT is where this axis should be judged**, and it is worse news. Its attack
events do carry targets and arguments, and its sabotage tasks are a scheming agent
under a legitimate user goal, which is our threat model rather than a
malicious-user one.

**SLEIGHT's 36.9% is not discrimination.** Containment and false-block move
together at every operating point, so the layer is refusing a fraction of
everything and being credited for the attack share. Sweeping the velocity cap
makes it explicit: 65.5/65.6, 55.5/55.3, 49.7/49.8, 43.9/42.4.

This is not a gap we are behind on. The published frontier catches 32% of SLEIGHT
at a 1% false-positive rate using a frontier model with extended thinking as a
monitor. No per-call authorization system contains content-defined harm, and
saying so is more useful to a buyer than a number that does not survive contact
with their traffic.

---

## Open-ended tasks, which is a different axis again

AgentDyn (arXiv:2602.03117) builds tasks whose correct next step cannot be known
in advance. Plan conformance, which costs utility at the margin on AgentDojo,
costs everything here: zero clean utility, 254 of 281 actions blocked, 21.67 human
interruptions per task.

Runtime replanning fixes it by growing the plan from the sealed goal rather than
denying deviation. The judge sees the goal, the tool catalog, and the action's
shape (tool name and verb class), and never sees tool output or argument values,
so an injection can cause an action to be *requested* but never reaches the judge.

| Suite | Configuration | Clean utility | ASR | Interruptions/task |
| --- | --- | --: | --: | --: |
| shopping | undefended | 66.7% | 16.7% | 0.00 |
| shopping | plan conformance | 0.0% | 0.0% | 20.67 |
| shopping | **+ replanning** | **50.0%** | **5.6%** | **1.83** |
| github | undefended | 83.3% | 61.1% | 0.00 |
| github | plan conformance | 0.0% | 0.0% | 12.17 |
| github | **+ replanning** | **16.7%** | **0.0%** | **8.50** |
| dailylife | undefended | 33.3% | 94.4% | 0.00 |
| dailylife | plan conformance | 0.0% | 0.0% | 1.33 |
| dailylife | + replanning | 0.0% | 0.0% | 1.83 |

Three quarters of undefended utility recovered on shopping at a third of the
undefended attack rate, and interruptions down from 20.67 to 1.83. github
recovers a fifth of undefended utility while holding ASR at 0.0% against an
undefended 61.1%.

**dailylife does not move.** Replanning recovers nothing there, and it is the
suite where plan conformance was already cheap (1.33 interruptions per task), so
the blocks were never the binding constraint. Reporting the two suites where the
mechanism works and omitting the one where it does not would misstate what it
buys.

---

## How these numbers are kept honest

Three headline results were withdrawn during this work, each caught by
measurement rather than review. The invariants that now fail the build:

- **The cap must not move when only attack traffic changes.** Catches a policy
  parameter derived from the label.
- **A calibrated policy is scored on data it did not see.** `run_benchmark`
  calibrates on half the clean tasks and scores the other half by default.
  Attack-bearing tasks never calibrate anything and are all still scored, so the
  containment denominator is unchanged and only the friction denominator shrinks.
- **Shuffling events inside a task must not move containment or false-block for
  any deployable rung.** Catches a loader whose ordering carries the label, which
  is what produced the +8.0.
- **No lower rung may contain an attack event a higher rung allows,** asserted per
  event rather than per rate. Caught four SLEIGHT attacks the full stack allowed.
- **Every arm of a benchmark must clear the ladder below the mechanism under
  test.** Without it, burst and flow would both be re-measuring scope.

Sources: `four_axes.md`, `burst.md`, `flow.md`, `agentdyn.md`, `pooled_asr.md`.

## One security regression this caught before it shipped

Runtime replanning, measured on AgentDojo travel, took clean utility from 50.0%
to 100.0% and **ASR from 11.1% to 22.2%**. A travel-booking goal plausibly implies
sending and booking, so the injected action was shape-consistent and the shape
judge admitted it with nothing else left to distinguish it.

It was worse than that. For an untargeted consequential action the destination
floor has no opinion at all, so pre-fix replanning extended on shape alone, which
made it strictly more permissive than `defer_allows_bound`, a flag this codebase
marks do-not-enable. That is the 641-of-833 untargeted majority, not an edge case.

A consequential off-plan action may now only be replanned when the binding floor
positively validated where it points. Re-measured: travel posts ASR 11.1% with
and without replanning, at 66.7% clean utility either way.
