# Why we fail where we fail

Every attack event we miss, across six corpora, analysed for what the missed
events have in common. The answer is sharper than "in-surface" and it points at
a specific mechanism rather than at a general limitation.

## The miss rate is bimodal, not a gradient

| Corpus | attacks allowed | rate |
| --- | --: | --: |
| ASB | 0 / 2,040 | 0% |
| IPI-Coding | 0 / 50 | 0% |
| RedCode | 1 / 718 | 0% |
| AgentThreatBench | 10 / 24 | 42% |
| SLEIGHT | 211 / 328 | 64% |
| AgentHarm | 611 / 652 | 94% |

There is no middle. We either contain essentially everything or essentially
nothing, which means a single property separates the two groups rather than a
quality difference in the attacks.

## The property: 77% of missed attacks have no target at all

Classifying every missed event by which fields were already granted:

| Cause | Count | Example |
| --- | --: | --- |
| tool, resource and action all granted, **and no target at all** | 641 | `run_stable_diffusion_model` / write / `None` |
| tool, resource and action all granted, target in scope | 188 | `read_file` / read / `/app/*` |
| resource and action granted, no target | 4 | `TodoWrite` / call / `None` |

**Our authority binds to targets.** Path scope, destination binding, and
protected zones all answer "what is this action pointed at". An action with a
granted tool and no target presents nothing for any of them to check, so it
passes by construction rather than by judgement.

The share of untargeted attacks predicts the miss rate exactly:

| Corpus | attacks with no target | miss rate |
| --- | --: | --: |
| RedCode, IPI-Coding, AgentThreatBench | 0% | 0% |
| SLEIGHT | 10% | 64% |
| AgentHarm | 100% | 94% |

ASB is the instructive exception: 100% of its attacks are untargeted and we
contain all of them, because they use tool names the agent was never granted.
Untargeted, but out of surface on a different axis, so the weakest rung catches
them.

AgentHarm's untargeted attacks use `send_email`, `post_on_x`,
`query_google_search`, `run_stable_diffusion_model`. All granted, all ordinary,
and the harmful and benign twins differ only in what the content *says*.

## The obvious fix is measurably worse than the problem

If an untargeted consequential action carries no evidence, the natural response
is to escalate rather than allow. We tested it: block any consequential action
with no bindable target.

| Corpus | contained now | with escalation | false-block now | with escalation |
| --- | --: | --: | --: | --: |
| AgentHarm | 6.3% | **43.7%** | 0.00% | **38.59%** |
| tau2 | n/a | n/a | 0.00% | **54.59%** |
| bfcl | n/a | n/a | 0.00% | 14.26% |
| ASB | 100% | 100% | 0.00% | 4.90% |
| atif | n/a | n/a | 0.00% | 2.48% |

It buys 37 points of containment on one corpus and destroys the system
everywhere else: **55% of legitimate actions blocked on tau2**, 14% on BFCL.
Untargeted consequential actions are overwhelmingly normal work. Sending an
email, posting an update, and running a search are what agents do, and a rule
that gates on "consequential with no target" gates on most of the job.

So the current default is not an oversight. It is the correct call given the
evidence available at that point in the decision, and the failure is an
information problem rather than a policy one.

## What would actually close it

The discriminating information is not in the target, so it has to come from
somewhere else. Three sources, in order of how deterministic they are:

**Aggregate and rate.** Volume, velocity, and distribution work without any
target at all, which is exactly why the aggregate rung is the only one that
contains bulk exfiltration over an allowed channel. It does not stop the first
harmful email, and it stops the hundredth. Our structuring and velocity work is
this, and it is the most defensible route because it stays deterministic.

**Parameter provenance.** AuthGraph's parameter-source policy asks not "where is
this pointed" but "which observation supplied this value". That gives an
untargeted action a checkable property it currently lacks, and it is the reason
their utility number is the best published.

**Intent.** ARGUS's entailment check asks whether an action is supported by
benign evidence alone. This is the only published mechanism aimed squarely at
the AgentHarm and SLEIGHT class, and it puts a model in the decision path, which
is why it belongs as an advisory tier feeding the two-signal gate rather than as
a blocker.

The plan-conformance envelope we already ship is a fourth source and it does
cover untargeted actions, since it judges whether a step belongs to the task at
all. It is absent from these deterministic replays because it needs a planner.
That is worth measuring next: the ladder numbers here are a floor for the
deployed system, not a description of it.

## The honest framing

Authorization binds what an agent may touch. Where harm is defined by what an
action touches, we contain essentially all of it, across 2,808 attack events
from four corpora. Where harm is defined by what an action *says* or *means*, no
per-call authorization system contains it, ours included, and the published
frontier does not either: an Opus 4.6 monitor with extended thinking catches 32%
of SLEIGHT at a 1% false-positive rate.

That boundary is worth stating plainly rather than obscuring, because a buyer
who deploys this against content-defined harm will discover it in production.

---

## Implemented: velocity, what it recovered, and a result we had to withdraw

`agentauth/capabilities/velocity.py`, exposed as the ladder rung
`task-scope+binding+budget+velocity`.

### The first version was invalid

It set the cap at `1.5x the benign effect count of the task being judged`, on the
reasoning that only benign events were consulted so no attack label could reach
the limit. That reasoning is wrong, and the corpora say so directly:

| Corpus | attack-bearing tasks with zero benign effect events |
| --- | --: |
| SLEIGHT | 45/45 (100%) |
| RedCode | 539/539 (100%) |
| ASB | 15/15 (100%) |
| AgentThreatBench | 16/24 (67%) |

Where every attack-bearing task has no benign effect volume, every one of them
was handed `cap = floor = 1`, and the second attack action onward was blocked
because the task was an attack. The limit was a function of the label. It
reported 24.7% containment on AgentHarm and 65.5% on SLEIGHT. **Neither number
was real and both are withdrawn.**

### The version that holds

The cap is now a single per-mandate constant, set at the largest number of effect
actions any *clean* task performs. That is what an operator sets from their own
logs, it never consults the task being judged, and it never consults an attack
event.

The observed maximum rather than a high percentile, because the two differ in
kind: at p99 the cap trips on the busiest 1% of legitimate work by construction,
and it did, costing BFCL 0.4% of its benign side and tau2 0.1% for no containment
in return.

| Corpus | cap | containment before | after | false-block before | after |
| --- | --: | --: | --: | --: | --: |
| AgentHarm | 5 | 6.3% | **14.3%** | 0.00% | **0.00%** |
| SLEIGHT | 17 | 35.7% | 35.7% | 35.37% | 35.37% |
| RedCode | 32 | 99.9% | 99.9% | 0.00% | 0.00% |
| ASB | 5 | 100% | 100% | 0.00% | 0.00% |
| IPI-Coding | 1 | 100% | 100% | 0.00% | 0.00% |
| AgentThreatBench | 5 | 58.3% | 58.3% | 0.00% | 0.00% |
| tau2 (14,842 benign events) | 9 | n/a | n/a | 0.00% | **0.00%** |
| BFCL (3,232 benign events) | 7 | n/a | n/a | 0.00% | **0.00%** |
| ATIF | 3 | n/a | n/a | 0.00% | **0.00%** |

**AgentHarm containment more than doubles, 6.3% to 14.3%, at zero measured
false-block cost on any corpus**, including the three benign-only sets totalling
over 18,000 legitimate events. AgentHarm and ASB have no clean task to calibrate
against, so both take the declared default of 5. The ladder invariants hold:
monotone containment, no added friction at a higher rung.

### What the corrected measurement also shows

**Velocity has no discrimination on SLEIGHT at any cap.** Sweeping the cap from 1
to 50, containment and false-block move together at every point: 65.5/65.6,
55.5/55.3, 49.7/49.8, 43.9/42.4. The mechanism was blocking a fraction of
everything and being credited for the attack share. Covert-intent attacks look
exactly like legitimate work in volume as well as in target, which is the same
boundary the section above describes, now measured on a second axis.

**A single cap shared across corpora is not viable**, confirming the earlier
global-cap rejection with a sharper number: RedCode's clean side runs to 32
effect actions per task and loses 17.4% of its benign traffic at the cap
AgentHarm wants. The limit belongs in the mandate, per class of work.

Velocity does not touch the first harmful action, and it never will. The eight
points it buys on AgentHarm are the attacks that need volume. The rest is a
single authorized-looking action whose harm is in its content, and no rate limit
reaches that.

Regression tests pin the invalid design out: `benchmarks/tests/test_ladder_invariants.py`
asserts the cap does not move when only attack traffic changes.
