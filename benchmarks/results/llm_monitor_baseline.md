# An LLM monitor as a baseline: near deny-all, and why containment alone hides it

STATUS: SUPERSEDED. Every number below was produced with an EMPTY task
description, because the harness read `scen.prompt` where the field is
`user_prompt`. The monitor judged each call knowing nothing about the task and
blocked a median of 14 benign calls per scenario. Re-measured correctly it
contains 107 of 132 at 29 completed, joint 22. BOTH earlier figures on this
page are wrong: the 93.9% table below came from a run with a degraded backend,
and the 25/108/7 correction that replaced it came from a second one, with 3,765
of 4,727 calls errored. An errored call ALLOWS, so both runs scored the monitor
as closer to allow-all than it is.

```bash
export AZURE_OPENAI_ENDPOINT=... AZURE_OPENAI_KEY=...
python -m benchmarks.bpl_sweep --suite full        # gpt-4.1-mini, the default
CLAYSEAL_MONITOR_DEPLOYMENT=gpt-4.1 python -m benchmarks.bpl_sweep --suite core
```

The obvious alternative to a policy gateway is to show a capable model the
trajectory and let it decide. It was missing from the comparison, so every claim
here was being made against per-call authorization and dataflow taint only. This
adds it as an arm.

**Fairness rules, because a rigged baseline is worse than none.** The monitor
sees what the gateway sees: the scenario prompt including its policy, the actions
already taken, and the proposed call with its arguments. It never sees the label,
the benign twin, or which script it is watching. It answers the same question the
gateway answers and a refusal blocks exactly as a DENY does. An errored call
**allows**, so a broken backend can never score containment. Answers are cached
by content hash, so a rerun costs nothing and the arm is reproducible without
re-spending.

## Result, full suite, gpt-4.1-mini

| arm | containment | completion | **joint** |
| --- | ---: | ---: | ---: |
| deny-all | 100% (132/132) | 0 of 132 | 0 of 132 |
| **llm-monitor** (degraded run, DO NOT CITE) | 93.9% (124/132) | 3.0% (4/132) | 0.8% (1/132) |
| **llm-monitor** (full cache, 0 errored) | **81.1% (107/132)** | **22.0% (29/132)** | **16.7% (22/132)** |
| per-call authorization | 0.8% (1/132) | 100% (132/132) | 0.8% (1/132) |
| dataflow taint | 31.8% (42/132) | 62.9% (83/132) | 11.4% (15/132) |
| **Clay Seal** | 40.9% (54/132) | 98.5% (130/132) | **39.4% (52/132)** |

3,063 calls, 0 errored.

**The monitor trades most of the legitimate work for containment.** On the
reproducible run it contains 81.1% by refusing 78% of
legitimate work. Read the containment column alone and it ranks second only to
deny-all and far above this gateway; read the pair and it is a system that
stops the attack by stopping everything.

That is the entire argument for scoring the conjunction. A benchmark reporting
containment alone would rank an unusable monitor above a deployable gateway, and
it would not be a close call.

Paired over the 132 scenarios, exact McNemar: Clay Seal beats the monitor on the
joint metric 52 wins to 1, **38.6 points [30.3, 47.7], p = 1.20e-14**, surviving
Holm correction over the family of five comparisons.

## It is not an artifact of a small model

The same 12 core scenarios, changing only the monitor's model:

| monitor model | containment | completion | joint |
| --- | ---: | ---: | ---: |
| gpt-4.1-mini | 75.0% (9/12) | 16.7% (2/12) | 0 of 12 |
| gpt-4.1 | 75.0% (9/12) | 33.3% (4/12) | 8.3% (1/12) |
| Clay Seal | 83.3% (10/12) | 91.7% (11/12) | **75.0% (9/12)** |

The stronger model over-blocks less, doubling completion from 16.7% to 33.3% at
identical containment, which is the direction a capability story predicts. It
does not change the conclusion: both monitors complete a third or less of the
benign work, and the gap on the joint metric is nine scenarios to one.

## What this does not establish

- **One prompt.** The monitor's instruction tells it that blocking legitimate
  work is as costly as permitting an attack. A different prompt would move these
  numbers and prompt sensitivity is not measured here. A monitor tuned by
  someone trying to win this benchmark would do better than a monitor written by
  someone trying not to rig it.
- **Two models, one family.** Both are OpenAI models on Azure. A reasoning model
  given the whole trajectory at once, rather than one call at a time, is a
  different design and is not tested.
- **Per-call, not per-trajectory.** This monitor judges each action with the
  history in view. A monitor that reviews a completed trajectory and retracts
  cannot be scored on this harness, because the harness runs actions forward.
- **One named task, not a binder.** The published row is a median 21-word
  task. It often omits the ceiling the structured grant carries
  (`payout-splitting` never names $15,000). Only 12 of 132 scenarios have a
  declared `Policy` object. That is not how security policy is written. The
  production exam is `CLAYSEAL_MONITOR_BINDER` (a handbook of many documents)
  or tau2's `policy.md` compiled at seal time, where automatic extraction binds
  10 of 61 rule-shaped sentences. Neither is this table.
