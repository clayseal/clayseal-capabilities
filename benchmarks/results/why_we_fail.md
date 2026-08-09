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
