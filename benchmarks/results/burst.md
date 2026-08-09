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

200 sessions per cell, cap calibrated per corpus.

| Corpus | cap | burst | contained | blast radius | clean false alarms |
| --- | --: | --: | --: | --: | --: |
| tau2 | 7 | 2 | 6.5% | 1 | 0.0% |
| tau2 | 7 | 5 | 76.5% | 3 | 0.0% |
| tau2 | 7 | 10 | **100%** | 4 | **0.0%** |
| tau2 | 7 | 20 | 100% | 4 | 0.0% |
| tau2 | 7 | 50 | 100% | 4 | 0.0% |
| tau2 | 7 | 100 | 100% | 4 | 0.0% |
| BFCL | 6 | 2 | 0.5% | 0 | 0.0% |
| BFCL | 6 | 5 | 27.0% | 4 | 0.0% |
| BFCL | 6 | 10 | **100%** | 5 | **0.0%** |
| BFCL | 6 | 20 | 100% | 5 | 0.0% |
| BFCL | 6 | 50 | 100% | 5 | 0.0% |
| BFCL | 6 | 100 | 100% | 5 | 0.0% |

**Blast radius** is how many of the burst's actions completed before the first
block, and it is the number that decides whether containment was worth having. A
compromised agent gets 4 extra authorized actions on tau2 and 5 on BFCL before
the layer stops it, whether it was trying for 10 or for 100.

**A burst of two is not contained, and should not be.** Two extra authorized
actions have not left the shape of the task, and a layer that flagged them would
be blocking legitimate work at the same rate. The detection threshold sits
between 5 and 10 on both corpora.

## What this does and does not establish

It establishes that the rung works on the threat it was built for: a compromise
performing a high volume of individually authorized, correctly targeted,
in-scope actions is stopped after a bounded number of them, with no false alarms
across 400 real sessions.

It does not establish anything about single-action harm, which is most of
AgentHarm and all of the needle benchmark, and no rate limit will.

The cap is the observed maximum of clean volume, so it rises with the size of
the calibration sample: at 200 sessions tau2 calibrates to 7, at 60 sessions to
3. An operator with more logs declares a looser limit and accepts a larger blast
radius. That trade is explicit and is the reason the limit belongs in the
mandate rather than in the library.

## Reproduce

```bash
.venv/bin/python -m benchmarks.burst --corpus tau2 --count 200 \
  --json benchmarks/results/burst_tau2.json
.venv/bin/python -m benchmarks.burst --corpus bfcl --count 200 \
  --json benchmarks/results/burst_bfcl.json
```
