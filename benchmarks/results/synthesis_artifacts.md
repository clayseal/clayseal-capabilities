# Synthesized corpora manufacture the signal they are used to measure

STATUS: current

`adequacy.py` reports that of 11 corpora, **2 can evaluate a per-action layer, 2
a trajectory layer, 1 a density layer, and 0 a provenance layer.** That is the
binding constraint on this project: four corpora carry no attack events at all,
and on `asb` and `injecagent` trajectory length alone separates benign from
attack at AUC 1.000.

The obvious fix, and the one the plan called for, is to synthesize attacks into
the benign corpora. `benchmarks/adversarial/attacks.py` has done this since the
beginning. **It makes the problem worse, in two different ways, and both were
invisible in the resulting scores.**

## 1. Appending is a length label

Every transform builds `benign + attack_events`, so a variant is strictly longer
than the benign trajectory it is scored against. Length alone as a classifier:

| corpus | benign median | attack median | length-only AUC |
| --- | ---: | ---: | ---: |
| bfcl | 1 | 2 | **1.000** |
| toolemu | 5 | 7 | 0.745 |
| tau2 | 4 | 6 | 0.626 |

An AUC of 1.000 means a detector that does nothing but count events scores
perfectly, and every other row on such a table is unreadable.

## 2. Appending manufactures provenance signal, which is worse

This is the one that matters, because it does not look like an artifact, it
looks like a result.

An appended attack runs at the END of a trajectory, by which point the session
has already ingested external content, so the attack action is taint-derived
almost by construction:

| corpus | benign taint | attack taint | gap |
| --- | ---: | ---: | ---: |
| tau2 | 24.0% | 46.5% | **+22.4pp** |
| toolemu | 79.2% | 100.0% | **+20.8pp** |
| atif | 84.3% | 99.4% | **+15.0pp** |

A 15 to 22 point gap reads as a provenance channel with real signal. It is
**positional**: not "attacks are untrusted-driven" but "later actions are
taint-derived, and an appended attack is always later."

`adequacy.py` already documents the same artifact with the sign reversed
RedCode attack tasks are single-event and begin cold, so 83.7% of benign actions
are taint-derived against **0 of 718** attack actions, a corpus that rewards an
inverted detector. Both directions are the same positional effect.

## The fix, and what it actually buys

`synthesize(..., length_matched=True)` substitutes attack events for benign ones
at a **drawn** position rather than appending them.

| channel | append | substitute (tail) | substitute (drawn) |
| --- | ---: | ---: | ---: |
| length AUC | 0.626 – 1.000 | 0.500 | **0.500** |
| position AUC | — | 0.742 – 0.901 | **0.520 – 0.605** |
| taint gap | +15 to +22pp | ~0pp | **−1.4 to +2.6pp** |

Tail substitution trades the length tell for a position one, which is why the
position is drawn. Variants whose source session is too short to host the attack
length-matched are **dropped, not appended as a fallback**, falling back would
reintroduce the shortcut on exactly the short sessions where it is strongest.
That costs volume: bfcl 1,150 variants becomes 744.

### It reduces the number of usable layers, and that is the point

| corpus | append | length-matched |
| --- | --- | --- |
| tau2 | all 4 layers "usable" | 3 — **provenance fails: no signal** |
| toolemu | all 4 "usable" | 3 — provenance fails |
| atif | all 4 "usable" | 3 — provenance fails |
| bfcl | **0** (shortcut 1.000) | 1 (per-action) |

Appending would have turned `provenance: 0 of 11` into an apparent 3 or 4 of 11.
Every one of those would have been a corpus scoring a provenance channel on
event position.

So the honest summary is not that the substrate got better. **It is that the
substrate is as bad as `adequacy.py` originally said, the standard way of
repairing it manufactures the signal it claims to add, and only `bfcl` moved
from unusable to one usable layer.**

## What this means for anything already measured

Any provenance or taint result computed on an append-synthesized corpus is
measuring position. `benchmarks/leaderboard.py` synthesizes by appending and is
the main such path. The default is unchanged (`length_matched=False`) so prior
numbers stay reproducible rather than silently shifting, and the flag is opt-in.

## Reproduce

```bash
python -m benchmarks.adequacy
pytest benchmarks/tests/test_synthesis_artifacts.py -q
```
