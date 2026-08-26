# What a long session costs

STATUS: current

```bash
python -m benchmarks.session_scaling --lengths 100,250,500,1000,2000,4000
```

`DeployableStack` with an intent envelope, one session, no attacks.

| actions in the session | total | mean per decision |
| --: | --: | --: |
| 100 | 0.01 s | 97 us |
| 250 | 0.02 s | 68 us |
| 500 | 0.04 s | 80 us |
| 1000 | 0.08 s | 75 us |
| 2000 | 0.19 s | 94 us |
| 4000 | 0.70 s | 176 us |

Fitted growth exponent across the range: **1.16**. An exponent near 1
means per-decision cost is flat; near 2 means the session is quadratic and the
last decision costs far more than the first.

## Why this was invisible

`latency.py` measures the ladder rungs, which are stateless per event, so its
numbers are flat in session length by construction and it reports 13.3 us at p50
for the full ladder. That is a true number about a different thing. The shipped
stack carries a trajectory, and the intent envelope re-assessed all of it on
every decision.

Every corpus here has short tasks. `agentharm` averages a handful of actions and
its longest is well under a hundred, so no benchmark in this repository ever ran
a session long enough for the shape to appear. An agent that runs for an hour is
a different regime, and it is the regime a production deployment is in.

## Measured before and after

| session | before | after |
| --: | --: | --: |
| 500 actions | 0.20 s | 0.03 s |
| 1000 actions | 0.75 s | 0.08 s |
| 2000 actions | 13.1 s at first measurement, 2.51 s after caching | **0.19 s** |
| growth exponent | 1.70 | **1.23** |

Three changes, in the order they were made and worth the smallest amount first.

**`surface_class` and the membership read are cached.** Profiled at 642,400
calls to one and 321,200 to the other over 800 decisions, against roughly 800
distinct paths. Membership has no cross-action state, so the same action re-read
at step 800 has the answer it had at step 1 and a value-keyed memo is sound. The
`str()` conversion stays outside the cache because `lru_cache` hashes before the
body runs, which is a defect this repository has already had once.

**The assessment resumes instead of rescanning.** The only state the loop
carries across actions is `steps`, which is append-only, and `satisfied`, which
counts phase occurrences; everything else is constant within a call. So a prefix
already assessed under the same comparability flag can be resumed, and the two
conditions that make that sound are checked rather than assumed: the cached
prefix must still be the head of this trajectory by object identity, and the
comparability flag must not have flipped.

**The equality is proved, not asserted.**
`python/tests/test_intent_envelope_incremental.py` holds the incremental result
against a from-scratch assessment over randomized trajectories at twelve seeds,
including the rollbacks the broker performs on a refusal, where a pop followed
by a different push leaves the length equal and the identity different. An
optimization inside an enforcement path that is subtly wrong is worse than the
cost it saves.

## What it cost

Nothing, on every corpus at once: sleight 44/311 benign and 46/122 in-surface,
agentharm 46/729 and 160/507, redcode 717/717 surface-leaving, asb 2040/2040,
injecagent 1597/1597, tau2 1 of 5441, bfcl 0 of 1200. Byte-identical to the run
before any of the three changes.

## What is still true

The residual exponent of 1.23 is `IntentConformance.conforms`, which asks
whether every step so far is in plan and is therefore O(N) per decision with a
very small constant. At 4,000 actions a decision costs 138 us against an LLM
round trip of hundreds of milliseconds, so it is roughly three orders of
magnitude below the thing it gates.

The trajectory itself is still unbounded: 1,621 bytes per action measured, so
162 MB at 100,000 actions in one session. That is a real limit and it is not
addressed here. `DecisionLog` already bounds its own retention with
`max_records`; the trajectory has no equivalent, and giving it one changes what
the phase-order landmarks can see, which is a semantic decision rather than an
optimization.
