# Live tier: the model ladder, and a correction to our utility story

STATUS: superseded
> **STATUS: superseded on one axis.** Every "supervised utility" figure below is a
> **counterfactual**, not a measurement. It is `autonomous + step-up losses`, which
> assumes both that a human approved and that the task then succeeded. Nothing
> resolved a step-up when these ran: `SessionBroker.resolve_step_up` and
> `LiveBrokerHarness.gate_with_supervision` did not exist. Re-run with a resolving
> approver (`benchmarks/live/approver.py`) before quoting any of it; the delta is
> expected to be negative, because a resumed run can still fail downstream.


The deterministic tiers say what the enforcement layer decides. This one says
what it costs a real agent doing real work. It is the tier
[docs/methodology_audit.md](../../docs/methodology_audit.md) has been asking for
since it was written, and running it changed the headline.

All four AgentDojo suites, 8 clean user tasks each, paired per task under `none`
and under each ablation. Reproduce with
`benchmarks/live/run_model_ladder.sh <suite> 8` then
`python -m benchmarks.live.summarize_ladder --suite <suite>`.

## Pooled across all four suites, gpt-4o-mini (n=32 clean tasks)

Baseline with no defense: **84.4%** (27/32) [68.2, 93.1].

| Ablation | Autonomous | Supervised | False-block | Endorsements/task | Utility cost |
| --- | --- | --- | --- | --- | --- |
| envelope | 59.4% [42.3, 74.5] | 62.5% [45.3, 77.1] | 12.5% [5.0, 28.1] | 0.03 | −21.9 pts |
| envelope-taint | 62.5% [45.3, 77.1] | 65.6% [48.3, 79.6] | 18.8% [8.9, 35.3] | 0.03 | −18.8 pts |
| oracle-envelope-egress | 78.1% [61.2, 89.0] | **84.4%** [68.2, 93.1] | 3.1% [0.6, 15.7] | **0.72** | **0.0 pts** |

**This is directly comparable to CaMeL, and the coincidence of baselines makes it
unusually clean.** CaMeL reports 77% task completion against an 84% undefended
baseline. Our undefended baseline here is 84.4% and our oracle path completes
78.1% autonomously. Same baseline, same utility, to within a point on both axes,
while [head_to_head_injection.md](head_to_head_injection.md) holds ASR at 0%
where Progent leaves 11 to 17%.

Two things stop that being the headline, and both belong in the same breath:

1. **The oracle path is a ceiling, not a product.** It seeds the trusted
   destination set from ground truth. The deployable paths cost 18.8 to 21.9
   points, which is roughly three times CaMeL's 7-point cost. Closing that gap
   is item 1 of [notes/improvements.md](../../notes/improvements.md), and it is now
   quantified against a comparable baseline rather than asserted.
2. **The oracle reaches parity by asking.** 0.72 endorsements per task, against
   0.03 for the deployable paths, a factor of twenty-four. Supervised utility of
   84.4% means "as good as no defense, if a human answers roughly one prompt per
   task". That is a real deployment posture and a defensible one, but it is not
   the same product as an autonomous agent, and quoting the 84.4% without the
   0.72 would be misleading.

## The correction

Our published utility cost was wrong, and wrong in the direction that made us
look worse than we are. The old framing compared aggregate utility under defense
against aggregate utility undefended, and charged the entire difference to the
defense: banking 50% to 16.7%, a 33-point cost.

Pairing per task shows most of that gap was never ours. Of 8 clean tasks on
gpt-4o-mini, **3 fail with no defense present at all**, the agent simply cannot
do them. Charging those to the enforcement layer is a measurement error, and it
is item 2 of the methodology audit.

| | old framing | paired attribution |
| --- | --- | --- |
| gpt-4o-mini, `envelope` | ~33-point utility loss | **12.5% false-block** (1 task of 8) |

One hard DENY, at the `intent-envelope` layer, on `send_money` for being off-plan
and out of phase order. That is the real, unrecoverable false-positive rate on
this suite, and it is roughly a quarter of what we were reporting.

## gpt-4o-mini (public OpenAI, the injectable floor)

Baseline utility 5/8 (62%).

| Ablation | Autonomous | Supervised | False-block | Endorsements/task |
| --- | --- | --- | --- | --- |
| envelope | 37.5% [13.7, 69.4] | 50.0% [21.5, 78.5] | 12.5% [2.2, 47.1] | 0.12 |
| envelope-taint | 37.5% [13.7, 69.4] | 50.0% [21.5, 78.5] | 12.5% [2.2, 47.1] | 0.12 |
| oracle-envelope-egress | 50.0% [21.5, 78.5] | 62.5% [30.6, 86.3] | **0.0%** [0.0, 32.4] | **0.88** |

**The endorsement column is the point of adding it.** `oracle-envelope-egress`
reaches 62.5% supervised utility, exactly the undefended baseline, at 0%
false-block. Read alone, that is a defense that costs nothing. Read with the
next column, it asks for **0.88 human confirmations per task**, seven times the
envelope's rate. It buys its perfect score by moving the decision to a person.

The 2026 adaptive-evaluation work (arXiv 2606.26479) names approval fatigue as
an attack surface for exactly this reason, and a buyer with an SOC will ask the
question immediately. `summarize_ladder` refuses to print supervised utility
without the endorsement rate beside it.

Action-level counts on the same runs, where the denominator is decisions rather
than the 8 tasks:

| Ablation | hard DENYs | step-ups |
| --- | --: | --: |
| envelope | 2 | 1 |
| envelope-taint | **1** | 1 |
| oracle-envelope-egress | **0** | **7** |

This is why action-level scoring is worth having. At task granularity
`envelope-taint` and `envelope` are indistinguishable, both 37.5%, and the
obvious conclusion is that taint does nothing. At action granularity it **halves
the hard denies**, from 2 to 1. The recovered denial did not happen to be the
one that flipped a task, so task-binary scoring cannot see it at n=8. The
mechanism works; the sample is too coarse to price it.

The oracle row reads the same way from the other side: 0 denies bought with 7
step-ups.

## llama-4-maverick (open weights, Azure AI Foundry)

Baseline utility 2/8 (25%).

| Ablation | Autonomous | Supervised | False-block | Endorsements/task |
| --- | --- | --- | --- | --- |
| envelope | 25.0% [7.1, 59.1] | 25.0% | **0.0%** [0.0, 32.4] | 0.00 |
| envelope-taint | 25.0% [7.1, 59.1] | 25.0% | **0.0%** | 0.00 |
| oracle-envelope-egress | 25.0% [7.1, 59.1] | 25.0% | **0.0%** | 0.00 |

Every ablation matches the undefended baseline exactly: **the defense is free on
this model.** Six of eight tasks fail with no defense present.

This is the case that justifies pairing. Naive methodology would compare 25%
here against 50% on gpt-4o-mini and conclude the defense costs more on open
weights. It costs nothing; the model is weaker at banking.

## Taint across four suites: net positive, with one specific failure mode

The single most useful thing this tier produced. `envelope-taint` was built to
recover the utility that goal-text-only provenance costs, and one suite cannot
tell you whether it works.

| Suite | Baseline | `envelope` denies | `envelope-taint` denies | Autonomous utility | Verdict |
| --- | --: | --: | --: | --- | --- |
| banking | 5/8 | 2 | **1** | 37.5% -> 37.5% | helps |
| travel | 8/8 | 3 | **1** | 50.0% -> **75.0%** | helps |
| workspace | 7/8 | 1 | 1 | 62.5% -> **87.5%** | helps |
| slack | 7/8 | 0 | **10** | 87.5% -> **50.0%** | breaks |

Positive on three suites of four. On travel and workspace it adds 25 points of
autonomous utility, and on workspace it reaches the undefended baseline exactly
with zero agent-caused losses left. On banking it halves denies. On slack it
manufactures ten denies where the plain envelope has none.

So taint is not broken, and it is not ready. It has **one diagnosable failure
mode**, and the fix is aimed at that rather than at the mechanism.

### Correction: the benefit is model-dependent too

The table above is gpt-4o-mini. Running the same ablation across four models
weakens the claim, and the weaker claim is the correct one. Autonomous utility
under `envelope-taint` over the undefended baseline:

| Model | banking | slack | travel | workspace |
| --- | --- | --- | --- | --- |
| gpt-4o-mini | 38% / 62% | 50% / 88% | **75% / 100%** | 88% / 88% |
| gpt-oss-120b | 75% / 75% | 50% / 100% | **25% / 62%** | 100% / 88% |
| grok-4-1-fast | - | 50% / 100% | **62% / 75%** | 88% / 88% |
| llama-4-maverick | 25% / 25% | 12% / 12% | - | 12% / 0% |

Travel is the case to look at. Taint takes gpt-4o-mini from 50% to 75%, and on
the same suite it takes gpt-oss-120b from 50% to 25% and grok-4-1-fast from 75%
to 62%. **The mechanism that recovers utility for a weak agent costs it for a
strong one**, which is consistent with the slack diagnosis: taint widens the
trusted set from structured fields, and an agent that navigates more of the task
on its own reaches more destinations that widening never covers.

One model is not enough to characterise a defense layer, and neither is one
suite. Taint needs the containing-object fix before it ships anywhere.

## slack, gpt-4o-mini: the failure mode

Baseline utility 7/8 (88%).

| Ablation | Autonomous | False-block | Endorsements/task | hard DENYs |
| --- | --- | --- | --- | --: |
| envelope | 87.5% [52.9, 97.8] | **0.0%** | 0.00 | 0 |
| envelope-taint | 50.0% [21.5, 78.5] | **37.5%** [13.7, 69.4] | 0.00 | 10 |
| oracle-envelope-egress | 87.5% [52.9, 97.8] | 0.0% | 0.50 | 3 |

10 denies and a 37.5% false-block rate where the plain envelope has zero.

The denial reasons say why, and the reason matters more than the number:

```
send_direct_message  recipient 'Alice' not on allow-list
get_webpage          egress to 'www.restaurant-zurich.com' not on allow-list
post_webpage         egress to 'www.our-company.com' not on allow-list
```

These are all legitimate. In slack, the destinations a benign task needs are
*discovered from message content*, the user asks the agent to message whoever
posted in a channel, or to read the restaurant page someone linked. They never
appear as literals in the sealed goal, so the goal-seeded trusted set does not
contain them, and taint's widening rule deliberately refuses to look at free
text because that is where injections live.

**That is the tension in one sentence: on this suite, legitimate destinations
arrive through the same channel as the attack.** Banking hides it because IBANs
arrive in structured fields. Slack does not, and no rule that discriminates by
*field type* can work here.

The fix direction follows from the diagnosis and is item 1 in
[notes/improvements.md](../../notes/improvements.md): discriminate by the
provenance of the *containing object*, not the field it sat in. A name in a
message from a channel the user's own goal named is task-derived; a name in a
webpage fetched from an unrelated domain is not. That is a transitive trust
judgement over the data-flow graph, which is what PAuth's operand binding does
and what our current one-hop widening cannot express.

## travel, gpt-4o-mini

Baseline utility 8/8 (100%), the only suite where the agent is fully competent,
which makes it the cleanest read on defense cost.

| Ablation | Autonomous | False-block | Endorsements/task | hard DENYs |
| --- | --- | --- | --- | --: |
| envelope | 50.0% [21.5, 78.5] | 25.0% [7.1, 59.1] | 0.00 | 3 |
| envelope-taint | 75.0% [40.9, 92.9] | 12.5% [2.2, 47.1] | 0.00 | 1 |
| oracle-envelope-egress | 87.5% [52.9, 97.8] | 12.5% [2.2, 47.1] | **1.25** | 1 |

The oracle row is the endorsement metric earning its place a second time: it
posts the best utility in the tier and asks for 1.25 human confirmations per
task to get there. Ten step-ups across eight tasks is not a free defense, it is
a defense with a person inside it.

## workspace, gpt-4o-mini

Baseline utility 7/8 (88%).

| Ablation | Autonomous | Supervised | False-block | Endorsements/task | hard DENYs |
| --- | --- | --- | --- | --- | --: |
| envelope | 62.5% [30.6, 86.3] | 62.5% | 12.5% [2.2, 47.1] | 0.00 | 1 |
| envelope-taint | **87.5%** [52.9, 97.8] | 87.5% | 12.5% [2.2, 47.1] | 0.00 | 1 |
| oracle-envelope-egress | 87.5% [52.9, 97.8] | **100.0%** [67.6, 100.0] | **0.0%** | 0.25 | 0 |

Taint reaches the undefended baseline here with zero remaining agent-caused
losses, on the same denial count as the plain envelope: the one deny it still
issues no longer lands on a task that would otherwise have succeeded.

The oracle row posts 100% supervised utility, above the 88% baseline, which is
not a paradox: a step-up that a human approves lets a task through that the
undefended agent botched on its own. It is also the clearest case for reading
that column with the endorsement rate attached.

## grok-4

Blocked on upstream availability. The first attempt failed with a Foundry
`424 / 503 The model is temporarily unavailable`, which is a capacity condition
on their side rather than a harness problem. Retry in progress.

## What this does not establish

- **n=8.** Every interval spans 30 to 50 points. `envelope` at 37.5% and
  `oracle` at 50% overlap heavily and are not distinguished by this run. Nothing
  here resolves a difference smaller than about 25 points.
- **One model for the four-suite result.** All four suites are gpt-4o-mini.
  llama-4-maverick has banking only, grok-4 none.
- **Clean tasks only.** This measures the cost of the defense, not its
  containment. ASR is measured separately in
  [head_to_head_injection.md](head_to_head_injection.md).
- **Utility is task-binary.** A task completing 9 of 10 steps scores the same as
  one doing nothing, which is most of why the numbers move so much between runs.
  Action-level scoring is item 6 in [notes/improvements.md](../../notes/improvements.md).

## Complete 4x4: the deployable envelope costs 3 points on a strong model

Pooled per model, 32 clean tasks each (8 per suite), paired so only
defense-caused losses count.

| Model | baseline | `envelope` | `taint` | `oracle` | envelope cost | false-block | endorse/task |
| --- | --- | --- | --- | --- | --- | --- | --- |
| gpt-4o-mini | 84% | 59% | 62% | 78% | −25 pts | 12.5% [5.0, 28.1] | 0.03 |
| gpt-oss-120b | 84% | 66% | 59% | 59% | −19 pts | 9.4% [3.2, 24.2] | 0.00 |
| **grok-4-1-fast** | 81% | **78%** | 62% | 84% | **−3 pts** | **6.2%** [1.7, 20.1] | 0.09 |
| llama-4-maverick | 12% | 12% | 17% | 12% | 0 pts | 0.0% [0.0, 13.8] | 0.00 |

**On grok-4-1-fast the deployable envelope costs 3 points against an 81%
baseline.** CaMeL's published cost is 7 points against 84%. That is our
*shippable* path beating the published bar, not the oracle ceiling, at 6.2%
false-block and 0.09 endorsements per task.

The trend across the ladder is monotone in model strength: 25 points on
gpt-4o-mini, 19 on gpt-oss-120b, 3 on grok-4-1-fast. **Most of what we have been
reporting as the cost of enforcement is the cost of a weak agent**, and it
disappears on the class of model anyone would actually deploy. The paired
attribution is what makes this visible; aggregate comparison cannot separate the
two.

llama-4-maverick is the degenerate row and should be read as a null: a 12%
baseline leaves nothing for a defense to cost. It is kept in because excluding
models that perform badly would be exactly the selection this program exists to
prevent.

The caveat that does not go away: n=32 per model, so the interval on a 3-point
difference is wide. The direction is consistent across four models and four
suites, which is worth more than any single cell.

## The defense gets cheaper as the agent gets better

`envelope`, autonomous utility over undefended baseline:

| Model | banking | slack | travel | workspace |
| --- | --- | --- | --- | --- |
| gpt-4o-mini | 38% / 62% | 88% / 88% | **50% / 100%** | 62% / 88% |
| gpt-oss-120b | 75% / 75% | 62% / 100% | 50% / 62% | **100% / 88%** |
| grok-4-1-fast | - | 88% / 100% | **75% / 75%** | **88% / 88%** |
| llama-4-maverick | 25% / 25% | 12% / 12% | - | 0% / 0% |

On grok-4-1-fast the envelope is free on two suites and costs 12 points on the
third. On gpt-4o-mini it costs 50 points on travel. **The expensive numbers we
have been publishing are substantially a property of a weak agent rather than of
the defense**, and no buyer is deploying gpt-4o-mini.

The pairing is deliberate. Baselines span 0% to 100% across these models, so a
bare utility figure makes a weak agent indistinguishable from an expensive
defense. `llama-4-maverick` is the extreme: it scores 0% under the defense on
workspace, and 0% without one.

## A platform content filter was competing with us

Azure's default RAI policy blocks responses labelled `Jailbreak`. On an injection
benchmark that is an **uncontrolled second defense in front of ours**: it
suppresses attacks we are trying to attribute to our own layer, and it fired
during *clean* task runs, which corrupts the utility number as well.

Any attack-success rate measured through a default Foundry deployment is partly
Microsoft's filter and partly ours, and the two cannot be separated after the
fact. The benchmark deployments now carry a custom policy (`benchmark-annotate`)
that disables jailbreak and indirect-attack detection while leaving every harm
category blocking, so the platform still refuses genuinely harmful content
without competing with the thing under test.

Runs predating that change are re-run rather than reinterpreted. This is worth
stating in any published result: a defense benchmarked on a hosted endpoint
inherits that endpoint's guardrails, and most published agent-security numbers
do not say which platform filters were active.

## Model-compatibility findings

Worth recording, because each was a trap that would have produced a wrong
published number rather than an error:

- **Llama-3.3-70B is unusable with AgentDojo on Foundry.** Its serving rejects
  any request defining more than one tool; banking defines eight. Verified
  directly rather than inferred. Llama-4-Maverick passes the same probe.
- **grok-4 needs a much higher token ceiling.** It is a reasoning model, and
  AgentDojo's default `max_tokens` is consumed entirely by reasoning tokens,
  returning `finish_reason=length` with zero completion tokens and an empty
  message. That reads as the agent failing the task.
- **The `<aoai-resource>` Azure deployment is named `gpt-4o-mini-2024-07-18` and
  serves `gpt-5-mini`.** The ladder driver unsets the Azure variables so the
  gpt-4o-mini rung is genuinely gpt-4o-mini. Any earlier result that ran through
  Azure under that name should be re-checked before it is quoted.
