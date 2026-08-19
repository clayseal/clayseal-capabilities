# The density rung: what it recovers, and what an adversary takes back

STATUS: current

Produced by `benchmarks/density_sweep.py` and `benchmarks/density_adaptive.py`,
three seeds each. **An earlier revision of this file reported the first table as
the result and called the generalization cliff flattened. The second table
withdraws most of that claim, and the second table is the one that matters.**

## The defect this was built against

`benchmarks/generalize.py` established it. Wildcarding the **path** grant by one
segment, holding every other dimension fixed:

| corpus | path exact | path up1 |
| --- | ---: | ---: |
| redcode | 99.86% | **33.29%** |
| ipi_coding | 100.00% | 30.00% |
| agent_threat_bench | 100.00% | 0.00% |

Generalizing the **tool** dimension costs nothing. So containment is one
mechanism — the attack path is outside a literally enumerated set — and it does
not survive a grant written the way an operator writes one.

## Result 1: against the shipped attack set, the cliff flattens

`DensityLadderEngine` composes the full ladder and adds a goal-conditioned
density over resource identity, calibrated through the runner's `observe_corpus`
hook on the clean half of the corpus, thresholded at the `1-alpha` quantile of a
**disjoint** slice of that clean half. `alpha` = 0.01.

| corpus | level | contained | + density | delta | FB | FB + density |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| redcode | exact | 99.86% | 99.86% | +0.0 | 0.00% | 0.00% |
| redcode | up1 | 33.29% | 99.86% | +66.6 | 0.00% | 0.00% |
| redcode | up2 | 33.29% | 99.86% | +66.6 | 0.00% | 0.00% |
| redcode | namespace | 33.29% | 99.86% | +66.6 | 0.00% | 0.00% |

Zero standard deviation across seeds, false-block an order of magnitude under
the declared budget. Taken alone this reads as the frontier moving rather than
sliding. Taken alone it is also misleading.

## Result 2: one relocation takes all of it back

A fixed attack proves nothing about an adversary who knows the defense. The
density blocks targets improbable under the cohort, so the adversary's move is
not a phrasing trick — it is to **relocate the malicious action to a target the
cohort already touches**. `density_adaptive.py` implements that as a ladder and
calibrates the defense on the *original* corpus, so the defender never retrains
on the attack it faces.

| mimicry level | contained | **by density** | false-block |
| --- | ---: | ---: | ---: |
| L0 original (`/etc/shadow`) | 99.86% | **66.57%** | 0.00% |
| L1 in-tree, novel subtree (`app/tmp/shadow`) | 33.29% | **0.00%** | 0.00% |
| L2 known parent, novel leaf (`app/shadow`) | 33.29% | **0.00%** | 0.00% |
| L3 exact known target (`app/document`) | 33.29% | **0.00%** | 0.00% |

33.29% is exactly the base ladder's containment at `up1`. **The density
contributes nothing once the attacker keeps its target under a root the cohort
uses.** Not degraded — zero, at the first rung of the ladder.

L3 scoring zero is expected and is not a defeat: an attacker confined to targets
the cohort routinely touches has been constrained, and what it can still
accomplish from there is a property of the deployment's data layout. **L1 is the
finding.** One relocation into a known root, keeping the malicious leaf name,
and the signal is gone.

## Why: the baseline learned exactly one bit

`TargetDensityScorer.concentration()` reports the escape mass `d*U/N` at each
node — the mass reserved for a child never seen there, which is the entire source
of the channel's discriminative power, and which is computable from clean traffic
alone.

| node | N | distinct (U) | escape mass |
| --- | ---: | ---: | ---: |
| `<root>` | 53 | 2 | **0.019** |
| `app` | 41 | 26 | **0.317** |

The root is concentrated, so a target outside the workspace is very surprising —
that is the 66.57% at L0. One level down it is diffuse: RedCode's benign side is
99 distinct paths over 314 events, so nearly every legitimate action visits a
fresh leaf and novelty there carries no information.

So on this corpus **the density is a learned version of the ACL's hardcoded
workspace boundary**, not an independent target-level signal. That is a real but
much narrower claim than the first table suggests:

> The density removes the need for an operator to *enumerate* the boundary. It
> does not add a signal the boundary did not already carry.

Removing the enumeration is worth something — it is the difference between a
mandate a human can write and one only a logger can produce, and it is why
Result 1 is not nothing. It is not the frontier-moving result the earlier
revision of this file claimed.

## The precondition, and why it ships as a diagnostic

The channel's power at depth *d* is governed by the escape mass at the nodes
along the path, and that is measurable **before deployment, from clean traffic,
with no attacks and no labels**. `concentration()` exists so a tenant can be told
in advance how much protection this can give them:

| corpus | depth | median U/N |
| --- | ---: | ---: |
| redcode | 0 (root) | 0.02 |
| redcode | 1 | 0.30 |
| agentharm | 0 | 0.03 |
| agentharm | 1 | 0.51 |
| toolemu | 0 | 0.01 |
| toolemu | 1 | 0.57 |

The pattern is consistent across all three: concentrated at the root, diffuse
immediately below it. On these corpora the channel can only ever have learned the
root. Whether real coding-agent traffic concentrates at depth — the same files
edited repeatedly across sessions — is an open question these benchmarks cannot
answer, and it is the thing to measure on live traffic before investing further.
That is a hypothesis, explicitly not a claim.

## Four bugs, none of which crashed

Each returned a well-formed, plausible number. That is the argument for
[../tests/test_density_rung.py](../tests/test_density_rung.py).

**1. A composed rung must calibrate what it composes.** Overriding
`observe_corpus` without delegating to `super()` left the velocity cap unset, and
an uncalibrated cap refuses clean traffic: **16.28% false-block, +0.0
containment**, all of the friction from the rung below while the density had
abstained. Nothing in the output attributed it.

**2. A key derived two ways is a key derived wrongly.** `fit` keys tries via
`goal_bucket`, which prefixes `goal:`; the decision path passed the raw kind.
Every lookup missed, so the rung **abstained on all 479 attacks** while reporting
a fitted scorer and a plausible 10.49-bit threshold. The sweep read +0.0 at 0.00%
false-block — indistinguishable in those columns from "correctly quiet".

**3. The calibration floor was counted in the wrong unit.** RedCode ships 50
clean tasks carrying 344 benign events. A floor of 30 *tasks* made the rung
abstain on a corpus with 172 calibration *actions* available: "the mechanism does
not work" when it meant "the mechanism was never switched on".

**4. Terminal nodes reserved zero mass for novelty.** A node where every observed
path ended has `U=0`, so `d*U/N` is exactly zero and any deeper continuation
scored `-log2(1e-12)` = 39.9 bits and was blocked outright. A legitimate
`app/documents/new.txt` against a baseline that only saw `app/documents` would
have been refused; these corpora hid it only because their benign paths are
uniformly shallow. Fixed with an add-one floor, `max(d*U/N, 1/(N+1))`. **Found by
`concentration()`**, which is the case for shipping the diagnostic beside the
estimator. Fixing it also removed a spurious 6.13% at L1 — that number was the
bug, not signal, and the honest L1 figure is 0.00%.

## The architectural change this produced

The adaptive result and the concentration measurement together say something the
first revision missed: **readiness is a depth, not a boolean.**

`benchmarks/concentration.py --curve` subsamples three corpora and finds
depth-1 novel-child surprise tracking one governing variable — observations per
distinct target — regardless of whether the corpus is synthetic or real,
tool-catalog or filesystem:

| obs/target | 1.7 | 3.0 | 4.5 | 8.3 | 75 | 196 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| novel-child bits at depth 1 | 1.8 | 2.6 | 3.2 | 4.1 | 5.1 | 6.1 |

Two hypotheses died here. It is **not** synthetic-vs-real: ATIF, the only corpus
of real agent sessions, is the *most* diffuse of all (44.3% repeat rate, depth-1
escape 0.417). It is **not** tool-catalog-vs-filesystem: tau2 and ATIF are both
tool catalogs and sit at opposite ends. It is sample size relative to namespace,
and nothing else.

So the channel is not weak — on these corpora it is **starved**, and the
operational question is not "does this work" but "how much clean traffic until
it does". That is answerable in advance, from benign traffic, with no attacks
and no labels.

`TargetDensityScorer.ready_depth()` implements it. On RedCode it returns **0**:
the root is estimated from 123 observations over 2 children (escape 0.003, a
genuinely sharp boundary), while depth 1 holds 68 distinct targets over the same
traffic — 1.8 apiece, which cannot separate anything. The scorer now stops
contributing surprise at the depth it stops having evidence.

A per-bucket *boolean* gate was tried first and is wrong in both directions: it
either discards the root RedCode does know or claims the leaves it does not. The
measured consequence of the depth form:

- The sweep is **unchanged** at +66.6 — the root signal was legitimately
  estimated all along.
- The adaptive ladder still reads **0.00% at L1/L2/L3**, but now *by
  construction* rather than as an empirical surprise. The model declares it
  knows the workspace root and nothing below it, and behaves accordingly.

That is the improvement. The limit did not move; it stopped being a footnote and
became a property the system states about itself. A rung that silently emits
noise below its evidence is the failure mode that produced every bug in the list
above — this one is now structural.

## Status

The rung is registered in the engine factory and **deliberately not in
`LADDER`**, with a test pinning it out. On this evidence it should stay out. What
would change that:

1. **Reach 5+ observations per distinct target on real traffic.** The whole
   thesis rests on cohort targets repeating, and the threshold is now a number
   rather than a hope. No corpus here clears it below the root; tau2 clears it
   easily at 196. Measure it on live agent logs — it is one query.
2. **A second corpus.** `ipi_coding` (5 clean calibration actions) and
   `agent_threat_bench` (9, against a floor of 60) both correctly abstain, so
   Result 1 is a single confirmed instance, not a rate.
3. **The parameter channel.** L1 mimicry keeps the malicious *leaf name* while
   moving the root. Target identity cannot see that; argument-level provenance
   might. This is the honest next mechanism, not a bigger density.

## Reproduce

```bash
python -m benchmarks.density_sweep --seeds 0 1 2 --levels 0 1 2 3
python -m benchmarks.density_adaptive --seeds 0 1 2
pytest benchmarks/tests/test_density_rung.py python/tests/test_target_density.py -q
```
