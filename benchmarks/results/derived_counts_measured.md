# The derived count rung, measured, including what it costs

STATUS: superseded in part

**Two claims below are wrong**, both found by re-measurement rather than by review. The derived-count rung is off by default and its measured cost is 8 further attacks caught out of 507 against 26 benign actions interrupted out of 278, roughly three interruptions per catch; that trade, not the figures below, is what the README quotes.

## Correction, and it is not a small one

Two claims below are wrong, and both were found by
[composed_detector.md](composed_detector.md).

**The sleight envelope column is deny-all.** The +62.3 points this file
attributes to wiring the intent envelope came from a membership tier comparing
two disjoint vocabularies: every sleight event is labelled
`resource="workspace"` while the goal surface is compiled from file paths, so
the tier refused every consequential action. It denied 204 of 311 benign events,
65.6%. With that fixed the honest sleight figures are **37.7% in-surface
containment at 14.1% benign cost**, against the 82.8% at 65.6% reported here.

**"Every one of those is a step-up rather than a refusal" is false for
sleight.** Re-run with `treat_step_up="allow"`, 204 of 311 benign events stay
blocked, because they are `Outcome.DENY` at the `intent-envelope` layer and no
supervisor can approve them. The sentence is correct for AgentHarm, whose 46
interruptions are step-ups and do flip. It was written as though one check
covered both corpora.

The AgentHarm numbers in this file stand. Everything in the sleight rows does
not, and the reasoning about reporting cost alongside containment stands more
strongly than when it was written: it was the cost column that exposed this, and
the containment column that hid it.

```bash
python -m benchmarks.coverage --datasets agentharm,sleight,agentleak --limit 4000 --engines deployable-stack-no-envelope,deployable-stack-no-counts,deployable-stack
```

The rung was built because 0 of 520 external corpus tasks declare a budget, so an
aggregate ceiling that waits to be declared is inert exactly where it is needed.
This is the measurement, attributed by difference across three arms of the same
stack, and it does not all go the way the build did.

## Containment

In-surface attack events, the population no floor rung can see.

| corpus | no envelope | envelope, no counts | envelope + counts |
| --- | --- | --- | --- |
| agentharm (507) | 24.9% [18.8%, 30.8%] | 30.0% [24.5%, 35.2%] | **31.6% [26.1%, 36.9%]** |
| sleight (122) | 20.5% [13.8%, 28.4%] | **82.8% [76.2%, 89.0%]** | 82.8% [76.2%, 89.0%] |
| agentleak (22) | 0.0% [0.0%, 13.6%] | 0.0% [0.0%, 13.6%] | 0.0% [0.0%, 13.6%] |

Two separate things, and only the first is large.

**The envelope was missing from the harness entirely**, and wiring it is worth
+5.1 points on AgentHarm and **+62.3 on sleight**. That is a harness fix, not a
new capability: `stack_factory.py` built the benchmark's stack with no intent
envelope, so every structural analysis routed through it measured a stack with no
goal-derived plan at all.

**The count rung adds +1.6 points on AgentHarm and nothing on sleight.** Eight
attack events of 507, zero of 122.

## What it costs

Benign events from the same corpora, no attacks.

| corpus | arm | allowed | interrupted |
| --- | --- | --- | --- |
| agentharm (278) | envelope, no counts | 278 | 0 |
| agentharm (278) | **envelope + counts** | 252 | **26 (9.4%)** |
| sleight (500) | no envelope | 495 | 5 |
| sleight (500) | **envelope, either way** | 190 | **310 (62.0%)** |
| bfcl (120) | either | 120 | 0 |

**Every one of those is a step-up rather than a refusal**, verified by re-running
with `treat_step_up="allow"`, where all 26 and all 310 become allows. The cost is
a person's attention, not a lost task. That is the difference the rung was
designed for and it is still a cost.

## The two verdicts

**The count rung: a defensible trade, and not a free one.** On AgentHarm it buys
8 additional contained attack events for 26 benign interruptions, roughly three
interruptions per attack. Whether that is worth it is a deployment decision and
not a default anyone should be given silently, so the numbers are here and
`compile_envelope(goal, derive_counts=False)` turns it off. It contributes
nothing at all on sleight, where the envelope alone already reaches 82.8%.

**The envelope on sleight: not a win, and it was already shipping.** +62.3 points
of containment bought with **62% of benign actions interrupted** is close to
deny-all behaviour on that corpus, and the containment number quoted on its own
would be badly misleading. This is not caused by anything built today: it is the
intent envelope as it already stood, newly visible because the harness now runs
it. It belongs on the list of things to fix rather than the list of results.

## Why this is reported at all

The containment column alone said the envelope was worth 62 points and the counts
worth 2, and both readings look like wins. The benign column says one of them is a
near-total refusal of legitimate work and the other costs three interruptions per
catch.

That is the same lesson `bpl_suite_composition.md` already encodes as the BOTH
column: containment is trivially winnable by refusing everything, and a number
reported without its cost is not a measurement. Running the cost side is what
stopped two apparent wins from being written up as wins.

## What did not move

AgentLeak stays at nothing under every arm, which is correct and structural: 22 of
22 of its attacks are a single authorized action that is itself the harm, so there
is no sequence for any aggregate rung to bound. No count, derived or declared,
can address that class.
