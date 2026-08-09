# Burst volume: the benchmark our corpora did not contain

Velocity limits are the only deterministic signal that survives an action having
no target, which is the shape of 641 of our 833 missed attacks. The rung is
implemented, costs nothing across 18,000+ benign events, and contains **zero**
attacks on every corpus we have.

That is a statement about the corpora, not a verdict on the mechanism. Velocity
is blind to the first occurrence by design; it bounds the blast radius of a
compromise already under way. RedCode's attacks are single destructive calls,
AgentHarm's are single harmful calls, SLEIGHT's are covert-intent calls, and the
long-horizon needle benchmark inserts exactly one malicious action by
construction. None of them contains a burst, so none of them can measure this.

`benchmarks/burst.py` supplies one.

## Construction

Sessions are real benign traffic from tau2 and BFCL, so the legitimate side is
not synthetic and the false-alarm number carries information.

The burst wears the session's own clothes. It reuses a tool, resource, verb and
argument shape the session already used legitimately, which means every rung
below velocity has to allow it. Verified directly rather than assumed:

    tau2: burst actions blocked by rungs BELOW velocity: 0/5000
    bfcl: burst actions blocked by rungs BELOW velocity: 0/5000

Anything the stack catches here is caught by rate alone. The test that pins this
is `benchmarks/tests/test_burst.py::test_every_burst_action_clears_the_rungs_below_velocity`;
without it the benchmark would be measuring scope again.

The cap is calibrated on clean sessions only, never on an attack, and a test
asserts it does not move when the burst grows by a factor of a hundred.

## Result

400 sessions per cell. The cap is calibrated on half the clean sessions, and the
false-alarm rate is reported on the **held-out** other half.

That split matters and it changed the answer. Calibrating and then measuring
false alarms on the same sessions is a tautology: the cap is the maximum of that
set's volume, so nothing in it can exceed the cap and 0.0% is arithmetic rather
than evidence. Held out, tau2 stays at 0.0% and BFCL costs 2.0%.

| Corpus | cap | burst | contained | blast radius | held-out false alarms |
| --- | --: | --: | --: | --: | --: |
| tau2 | 7 | 2 | 5.0% | 1 | 0.0% |
| tau2 | 7 | 5 | 74.8% | 3 | 0.0% |
| tau2 | 7 | 10 | **100%** | 4 | **0.0%** |
| tau2 | 7 | 20 | 100% | 4 | 0.0% |
| tau2 | 7 | 50 | 100% | 4 | 0.0% |
| tau2 | 7 | 100 | 100% | 4 | 0.0% |
| BFCL | 5 | 2 | 2.3% | 1 | 2.0% |
| BFCL | 5 | 5 | **100%** | 4 | **2.0%** |
| BFCL | 5 | 10 | 100% | 4 | 2.0% |
| BFCL | 5 | 20 | 100% | 4 | 2.0% |
| BFCL | 5 | 50 | 100% | 4 | 2.0% |
| BFCL | 5 | 100 | 100% | 4 | 2.0% |

**Blast radius** is how many of the burst's actions completed before the first
block, and it is the number that decides whether containment was worth having. A
compromised agent gets 4 extra authorized actions on tau2 and 5 on BFCL before
the layer stops it, whether it was trying for 10 or for 100.

**A burst of two is not contained, and should not be.** Two extra authorized
actions have not left the shape of the task, and a layer that flagged them would
be blocking legitimate work at the same rate. The detection threshold sits
between 2 and 5 on BFCL and between 5 and 10 on tau2.

**BFCL costs 2.0% of held-out legitimate sessions.** That is the price of the
tighter cap its traffic calibrates to, and it is the number to quote, not the
0.0% the calibration set reports.

## Is the 100% real, or did we build the benchmark to fit the mechanism?

The benchmark and the mechanism were written by the same hand on the same day, so
the question deserves an experiment rather than an assurance. Each row below is a
degree of freedom that was fixed arbitrarily when the benchmark was written; the
attacker varies it and the mechanism does not know in advance.

| Attacker variant | contained |
| --- | --: |
| repeat one action (as built) | 100.0% |
| vary the tool on every action | 100.0% |
| vary the verb class on every action | 100.0% |
| vary the resource on every action | 100.0% |
| interleave with legitimate work | 100.0% |

That survives because the aggregate `effect` class puts every effect verb in one
bucket, so changing the tool, verb or target does not create a second budget.
That is a property of the mechanism rather than of the benchmark.

**Two variants the benchmark never tried, and both work.**

**Splitting across sessions.** `SessionVelocity` is per object, so a new session
brings a new empty window. A declared cap of seven effect actions per hour
admitted **fifty-six** when the same work was split across eight sessions. This is
the same control the structuring work already showed an adversary resets at will,
and `principal_ledger.py` exists because of it; nobody had applied the lesson
here. `PrincipalVelocity` now keys the window to the mandate rather than the
conversation, and the same eight sessions get seven.

**Going slower.** Forty sends at ten-minute intervals pass a cap of seven per
hour, because four per hour is not a burst. A rate limit bounds the rate and not
the total, and a patient adversary simply goes slower. So the 100% above means
100% of bursts *above the declared rate*, and quoting it without this sentence
overstates it. There is a test asserting exactly this.

## What this does and does not establish

It establishes that the rung works on the threat it was built for: a compromise
performing a high volume of individually authorized, correctly targeted,
in-scope actions is stopped after a bounded number of them, at a held-out
false-alarm cost of 0.0% on tau2 and 2.0% on BFCL.

It does not establish anything about single-action harm, which is most of
AgentHarm and all of the needle benchmark, and no rate limit will.

The cap is the observed maximum of clean volume, so it rises with the size of
the calibration sample: at 200 sessions tau2 calibrates to 7, at 60 sessions to
3. An operator with more logs declares a looser limit and accepts a larger blast
radius. That trade is explicit and is the reason the limit belongs in the
mandate rather than in the library.

## Reproduce

```bash
.venv/bin/python -m benchmarks.burst --corpus tau2 --count 400 \
  --json benchmarks/results/burst_tau2.json
.venv/bin/python -m benchmarks.burst --corpus bfcl --count 400 \
  --json benchmarks/results/burst_bfcl.json
```
