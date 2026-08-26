# The floor and the detector, composed, and what the containment column hid

STATUS: current

```bash
python -m benchmarks.composed --datasets agentharm,sleight --limit 4000 --alphas 0.05,0.20
python -m benchmarks.coverage --datasets sleight,agentharm,agentleak --limit 4000 --engines deployable-stack
```

**Correction, 2026-08-24.** The operating curve below was first published from a
SINGLE split at seed 7. On `sleight` the held-out split is 18 tasks and the
between-seed standard deviation is 6.4 points of containment and 5.1 of benign
cost, so that draw sat near the bottom of a range it never showed and the
detector's apparent contribution swung from nothing to seven points depending on
the seed. Every cell is now a mean over five splits with its spread, and the
"roughly three interrupted benign actions per contained attack" figure that
follows from one seed is wrong: across seeds the exchange rate is closer to one
to one. `benchmarks/composed.py` now needs a single seed to be asked for.

This repository carried two evaluations that never met. `coverage.py` measured
the deterministic authorization stack per action. `core/detector_eval.py`
measured the conformal behavioural detector per trajectory. `SessionBroker`
composes them and always has, but `DeployableStack.from_goal` takes
`detector=None` and `stack_factory.py` never passed one, so every published
number for the shipped stack described a stack with the behavioural layer
switched off.

Composing them found something bigger than the composition.

## What was wrong: a membership test between disjoint vocabularies

Two tiers compile a goal into allowed resource CLASSES and refuse an action
whose class is not a member: `IntentEnvelope._membership` in the authorization
path and `TypedGoalEnvelope.assess` in the detector. Both guarded the case where
the surface is EMPTY. Neither guarded the case where it is DISJOINT.

On `sleight` every event is labelled `resource="workspace"` while the goal
surface is compiled from file paths. The two vocabularies never intersect, so
both tiers refused every consequential action, and the information needed to
decide correctly sat unread in `meta["path"]`, inside the goal surface the whole
time. A third defect compounded it: `resource_class` splits on the first
separator, so **every absolute path classes to the empty string** and
`/data/models/x` was indistinguishable from `/etc/shadow` and from nothing.

| tier | before | after |
| --- | --- | --- |
| intent envelope, sleight benign events denied | 204/311 (65.6%) | 44/311 (14.1%) |
| detector, sleight benign trajectories blocked | 13/18 (72.2%) | 0/18 |
| detector, sleight attack trajectories contained | 18/18 (100.0%) | 17/18 (94.4%) |

The detector was blocking benign trajectories at conformal p-values of 0.523,
0.709 and 0.912, because the envelope tier sits outside the conformal budget:
no choice of alpha softened it, which is why the first version of the sweep
below was flat in alpha. The fix is in `monitor/surface.py`, one reading used on
both sides of every membership test, and a tier may refuse only once something
in the session has matched its surface at least once.

**The detector now contains 17 of 18 sleight attack trajectories (94.4%) and
blocks 0 of 18 benign ones**, upper bound 18.5% on that second figure at n=18. That is the same instrument that was blocking 72% of benign
work an hour earlier, and nothing about its statistics changed.

## Three containment numbers that were deny-all

None of the three reads as deny-all from its containment column.

| claim, as published | what it was |
| --- | --- |
| intent envelope worth **+62.3 points** on sleight | 65.6% of benign events denied by a category error |
| envelope contains **82.8%** of sleight in-surface attacks | deny-all; the honest figure is 37.7% |
| detector: **83.3% contained, 0.0% false-block (no denominator published)** | not reproducible; the code gave 18/18 contained at 13/18 false-block |

`bpl_suite_composition.md` already encodes the lesson as the BOTH column, and
`deny-all` has been a control in the BPL sweep from the start. The structural
and detector analyses never had one. `check_claims` now carries a third ratchet,
`costless`, which counts files reporting containment that never name what it
cost: **8 at the baseline**, and it only turns one way.

## A note on the unit, added later

Every figure below is per EVENT. `session_units.md` measures the same runs per
SESSION and the two disagree in opposite directions: containment reads higher
per session because stopping an attack's first action prevents the rest, and
cost reads higher per session because one refusal can derail a task. Neither
unit is wrong and quoting one alone picks a side.

## The composed operating curve

Detector fit one-class on benign trajectories from a task-level train split,
never seeing an attack label. Both arms scored on the same held-out tasks.

### sleight (25 tasks fit, 18 held out, mean of 5 splits)

| arm | surface-leaving | in-surface | benign interrupted |
| --- | --- | --- | --- |
| floor only | 100.0% sd 0.0% n=5 | 40.0% sd 6.4% [34.5%, 52.4%] n=5 | 13.5% sd 5.1% [6.2%, 19.8%] n=5 |
| + detector, alpha=0.05 | 100.0% sd 0.0% n=5 | 44.6% sd 8.9% [34.5%, 59.5%] n=5 | 21.7% sd 6.2% [12.4%, 30.2%] n=5 |
| + detector, alpha=0.20 | 100.0% sd 0.0% n=5 | 53.0% sd 7.5% [45.9%, 66.7%] n=5 | 32.6% sd 6.8% [24.0%, 39.8%] n=5 |

### agentharm (211 tasks fit, 141 held out, mean of 5 splits)

| arm | surface-leaving | in-surface | benign interrupted |
| --- | --- | --- | --- |
| floor only | 100.0% sd 0.0% n=5 | 31.7% sd 1.5% [30.2%, 34.5%] n=5 | 6.6% sd 1.3% [4.3%, 8.3%] n=5 |
| + detector, alpha=0.05 | 100.0% sd 0.0% n=5 | 35.1% sd 2.7% [30.9%, 38.3%] n=5 | 9.5% sd 4.0% [5.6%, 16.6%] n=5 |
| + detector, alpha=0.20 | 100.0% sd 0.0% n=5 | 46.7% sd 5.5% [38.9%, 54.3%] n=5 | 25.4% sd 5.8% [19.1%, 32.8%] n=5 |

The spread is the point of this table. On `agentharm`, 141 held-out tasks, the
floor's containment moves 1.5 points across splits and the reading is stable. On
`sleight`, 18 tasks, it moves 6.4, and any single-split number from that corpus
should be read as one draw from a wide distribution rather than as a measurement.

### agentleak

16 tasks fit, 11 held out, and no detector arm: too little benign traffic to
calibrate on. An uncalibrated conformal test returns p=1.0 and flags nothing, so
reporting it as an arm would be reporting a configuration that does no work.

## Reading the curve, including the part that does not favour us

**Both axes are monotone in alpha on AgentHarm**, which is what a conformal
control has to do and is the evidence that the dial is real.

**The exchange rate is close to one to one, and depends on alpha.** Across five
splits on AgentHarm the detector buys 3.4 points of in-surface containment for
2.9 points of benign interruption at alpha=0.05, and 15.0 points for 18.8 at
alpha=0.20. On sleight, 4.6 for 8.2 and 13.0 for 19.1. The single-seed reading
this file first carried said three interrupted benign actions per contained
attack, which no seed supports. Whether one to one is worth paying is a
deployment decision and not a default anyone should be handed silently, so the
curve is here and the composed arm is opt-in.

**Trajectory-level containment flatters a per-action gateway, and the gap is
large.** The same detector is 17/18 contained at 0/18 false-block per TRAJECTORY, and worth +8 points
at +15 points of cost per EVENT. A trajectory counts as contained if any one of
its steps is blocked, so a detector that catches the last step of an attack
scores 100% there and one event here. The event-level column is what a
deployment experiences per call, and it is the one to quote.

**Composition is not monotone.** A blocked action is rolled back out of the
trajectory and its budget reservations released, so blocking early changes what
every later tier sees, and on individual splits the detector arm can contain
less than the floor alone. Reported rather than tuned away.

**The abstention this fix introduced was measured, not argued.** Making a tier
wait for its surface to match once creates a session in which it never speaks,
so the question is what that costs. On `redcode` **599 of 650 sessions never
become comparable**, and surface-leaving containment there is 717 of 717 with 0
of 344 benign events interrupted; `asb` is 2040 of 2040 and `injecagent` 1597 of
1597, both at no benign cost. Every session that becomes comparable at all does
so by its second action. The reason the hole is not a hole: a session that never
matches the surface is one where the tier would otherwise have refused every
action including all benign work, so the choice there was never between
enforcement and abstention. `test_surface_comparability.py` pins both halves.

## What did not move, and why that is correct

`agentleak` stays at nothing under every arm. 22 of 22 of its attacks are a
single authorized action that is itself the harm, so there is no sequence for
any aggregate rung and no trajectory for any behavioural one. Zero there is
structural. It is also why the detector cannot be calibrated on that corpus at
all, and the module says so rather than reporting an inert arm as a result.

## What this changes about the wall

The in-surface wall is real and it is lower than it was. The shipped floor now
contains 37.7% of sleight and 31.6% of AgentHarm in-surface attack events, at
14.1% and 6.3% benign cost, where the previous figures were 82.8% at 65.6% and
31.6% at 6.3%. The first pair is a genuine improvement in both columns at once;
the honest description of the old sleight number is that it was not a
measurement of the envelope.
