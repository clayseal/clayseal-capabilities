# The behavioural baseline: the null first, then the power

STATUS: current

```bash
python -m benchmarks.behavior_drift --dataset agentharm --trials 30 --alpha 0.05
```

176 sessions, split at random into an approval half and a later half, 30 times.

| condition | verdict is approaching-the-boundary |
| --- | --: |
| **nothing changed** (the null, alpha=0.05) | **2/30 (7%)** |
| 10% of later sessions carry the corpus attacks | 9/30 (30%) |
| 25% of later sessions carry the corpus attacks | 20/30 (67%) |
| 50% of later sessions carry the corpus attacks | 29/30 (97%) |
| 100% of later sessions carry the corpus attacks | 30/30 (100%) |

The null is what decides whether this is deployable. A monitor that fires on an unchanged workload is one that gets switched off, and the workload here is deliberately heterogeneous: two random halves of agentharm do not contain the same tasks.

## The boiling frog: why the baseline is sealed

Contamination rises 5% per period. The same traffic is compared against
the SEALED approval baseline, and against the PREVIOUS period as a rolling baseline
would.

| period | contaminated | vs sealed baseline | vs previous period |
| --: | --: | --- | --- |
| 1 | 5% | unchanged | unchanged |
| 2 | 10% | changed-inside-the-grant | changed-inside-the-grant |
| 3 | 15% | changed-inside-the-grant | unchanged |
| 4 | 20% | approaching-the-boundary | unchanged |
| 5 | 25% | approaching-the-boundary | changed-inside-the-grant |
| 6 | 30% | approaching-the-boundary | unchanged |
| 7 | 35% | approaching-the-boundary | unchanged |
| 8 | 40% | approaching-the-boundary | changed-inside-the-grant |
| 9 | 45% | approaching-the-boundary | unchanged |
| 10 | 50% | approaching-the-boundary | unchanged |

**Fired against the sealed baseline: 7 of 10. Against the previous period: 0 of 10.**

Every drift tool re-baselines periodically, which is right when the thing tracked is
a product and wrong when it is an authority. A baseline that moves with the traffic
makes each period look like the last, and a drift arriving a few points at a time is
never a change against anything. This is the measurement behind sealing the baseline
at approval rather than refreshing it.

## What the shape of that curve means

**The null is 2 of 30 at alpha 0.05**, which is what a calibrated test looks
like: with 30 trials, seeing two at a nominal 5% has probability around 26%, so
this is sampling noise rather than miscalibration. It matters because the
workload is deliberately heterogeneous. Two random halves of `agentharm` do not
contain the same tasks, the token distributions genuinely differ, and **27 of
those 30 splits are correctly reported as `changed-inside-the-grant`**: the
workload moved and its authority did not. A monitor that reported those as
incidents would be switched off inside a month, and that verdict is the reason
this one would not be.

**Power rises monotonically and needs roughly a quarter of sessions affected**
to be more likely than not to fire. It is not an instrument for a single
compromised session, and it should not be: one session acting outside its grant
is the floor's job, and the floor contains 100% of surface-leaving attacks
across more than 4,400 events.

That boundary is the right one, because the four things an enterprise means by
drift are all population-level:

| the fear | what changes | visible here as |
| --- | --- | --- |
| the provider swapped the model behind the endpoint | most sessions | novel action shapes, friction |
| someone edited a system prompt with no review | most sessions | novel action shapes |
| tools and grants grew a request at a time | the grant itself | `baseline-void` on the policy digest |
| approved on eval traffic, production differs | most sessions | `baseline-no-longer-describes-the-workload` |

None of those is a single rare event, and none is observable where it happens.
An enterprise cannot diff its vendor's weights and often cannot diff its own
prompt history. All four change what the agent does, and every action already
passes the authorization boundary typed and normalised.

## The channel a distributional monitor cannot have

`headroom` is the fraction of a ceiling a session consumes, and it is blind in
the table above because these corpora declare no budgets: 0 of 520 tasks do,
which is the same gap `external_corpora_structure.md` measures. Its value is
demonstrated in `test_behavior_baseline.py` rather than here, on the case that
separates this from drift monitoring:

- a workload whose action distribution changed COMPLETELY while staying at 10%
  of its ceiling is not an alarm;
- a workload whose action distribution is IDENTICAL and which now runs at 88%
  of a ceiling it used to touch at 12% is.

On the evidence a distributional test reads, the second is the unchanged one.
Only a component that knows where the permitted region ends can rank those two
the right way round, and the authorization layer is the only one that does.

## What is not claimed

The baseline cannot attribute a change to its cause. A model swap, a prompt
edit and a genuine shift in user demand are indistinguishable from here, and
inventing an attribution would be the most tempting thing to add and the least
defensible. It reports that behaviour moved toward the boundary, with the
channel that moved and the p-value, and re-certification is a human decision.

It also cannot see a change that stays well inside the grant, which is
deliberate rather than a limitation: that change did not increase what the agent
is able to do.
