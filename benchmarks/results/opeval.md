# Operating-point evaluation: the target-identity channel

STATUS: current

Produced by `python -m benchmarks.opeval`, working tree, five seeds. This file
tests one falsifiable prediction and reports what happened, including where the
prediction failed.

## The prediction

`monitor/action.py` reduces an action to `verb|tool|resource_class`, and
`resource_class` collapses every concrete resource to its scheme. Measured on
this repo's own loaders:

| corpus | distinct action tokens | distinct paths |
| --- | ---: | ---: |
| redcode | **4** | 248 |
| sleight | **10** | 168 |

All 248 RedCode paths are the single symbol `workspace`. On SLEIGHT the benign
and attack histograms match almost cell for cell and **100% of attack actions
carry a token that also occurs in benign**; on RedCode, 77.5%. The behavioral
layer is being asked to separate two distributions that are, in its own
representation, the same distribution.

Prediction: adding a second channel that models *which* resource an action
reached for, a backoff density over the resource tree, fit only on benign
traffic, with no grant and no enumerated paths, recovers the discrimination,
and does so without the operator writing anything.

## Result

Detection with the threshold pinned so the benign block rate is 1%. Benign
population pooled from BFCL where a corpus's own benign side cannot resolve the
rate (RedCode ships 718 risky ops against ~50 benign-carrying tasks; the suite
is designed to be scored against BFCL and `BENIGN_POOL` names the pairing).

| corpus | scorer | n (b/a) | AUC | pAUC@1% | det@1% | lift@1% | steps* |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| redcode | deny-all | 781/297 | 0.500 | 0.500 | 0.0% | 0.00 | – |
| redcode | ngram | 781/297 | 0.425 | 0.497 | 0.0% | 0.00 | – |
| redcode | **target** | 781/297 | **1.000** | **1.000** | **100.0%** | 61.2 | 1 |
| redcode | ngram+target | 781/297 | 0.952 | 0.868 | 73.7% | 74.4 | 1 |
| ipi_coding | ngram | 789/16 | 0.602 | 0.497 | 0.0% | 0.00 | – |
| ipi_coding | **target** | 789/16 | **1.000** | **1.000** | **100.0%** | 53.2 | 2 |
| agentharm | ngram | 76/65 | 0.375 | n/r | n/r | n/r | – |
| agentharm | target | 76/65 | 0.628 | n/r | n/r | n/r | – |
| sleight | ngram | 18/18 | 0.472 | n/r | n/r | n/r | – |
| sleight | target | 18/18 | 0.511 | n/r | n/r | n/r | – |

Across seeds 0–4, RedCode `target` det@1% is 100.0 / 100.0 / 100.0 / 100.0 /
99.7 and `ngram` is 0.0 at every seed with AUC 0.380–0.457, consistently *below*
chance. The effect is not a seed artifact.

**The prediction holds on the target-defined corpora and fails on the
content-defined ones**, which is the result one would want: SLEIGHT sabotage
writes subtly wrong code to the *same* files the benign twin touches, so target
identity carries no signal there and the channel correctly reports ~chance
(0.511) rather than manufacturing one. That matches the corpus's existing
caveat. AgentHarm moves 0.375 → 0.628, real but modest, consistent with its
standing as a content ceiling rather than an authorization win.

## Three things this is not

**Not a replacement for the ACL, and not the same signal.** On RedCode the ACL
and the density both key on path location. The difference is where the boundary
comes from: the ACL needs an operator to enumerate exact paths and loses 2/3 of
its containment when that enumeration is generalized one segment
(99.86% → 33.29%). The density was fit from benign traffic with no grant at all.
That is the claim, the discrimination survives without configuration, not that
path location is a new signal.

**Not yet wired into the enforcement path.** This is a scorer measured offline.
Composing it into `TrajectoryDetector` behind the conformal gate is the next
step, and until that lands no deployment claim follows from these numbers.

**Combination: the prediction held, and it was not enough.** `ngram+target`
sums raw surprises measured on different scales and the noisier channel drags the
signal. Replacing the sum with per-channel conformal p-values combined by
Fisher's method (`conformal-combo`) does what was predicted, detection at a 1%
budget on RedCode goes **42.4% -> 73.7%**, and still loses badly to the target
channel alone at **100.0%**.

That is the more useful result. On RedCode the n-gram channel has AUC 0.425,
*below* chance: it is anti-correlated with the label. No rescaling fixes a
channel that carries negative information, so the lesson is **channel selection,
not channel fusion**.

And selection has a hard constraint worth stating plainly: a channel's
*calibration* validity is checkable on benign traffic alone (are its p-values
uniform on held-out clean data?), but its *discriminative skill* is not. The
n-gram channel here is perfectly well calibrated and still useless. Deciding
which channels to include therefore requires some labelled attacks, it cannot be
done from clean traffic the way the density's readiness check can. That is a real
limit on how far a purely one-class design can be pushed.

Weights are left untuned throughout: a weighting fitted on these corpora would be
exactly the eval-fitting this exercise exists to remove.

## What the metric caught

The `deny-all` row is a constant scorer, permanently in the table. It earned its
place twice during this work:

1. **A tie-handling bug in the metric itself.** Taking the k-th largest benign
   score as the threshold blocks every benign sharing that score. For a constant
   scorer that is the whole corpus, so "detection at 1% FPR" read **100%** while
   the achieved FPR was also 100%. Fixed in `threshold_at_fpr` by evaluating
   candidate thresholds rather than indexing, and pinned by
   `test_the_fpr_budget_is_never_exceeded_on_adversarial_tie_structures`.

2. **A length leak in the harness.** RedCode's benign and attack events live in
   largely disjoint tasks, so a task's benign side is frequently empty. An empty
   trajectory scores 0 under every scorer while a non-empty attack scores above
   it, making trajectory length a perfect label, `deny-all` scored **AUC 1.000**
   on it. Both sides now require at least one action.

Neither was anticipated. Both were caught by a control row that costs nothing to
carry, which is the argument for carrying it permanently.

## Non-measurements, now excluded

tau2, BFCL, ToolEmu and ATIF carry **zero attack-labeled events**: their "attack"
trajectory is the benign one unchanged. Scoring them compares a distribution
against itself and returns AUC 0.500 for every scorer including a perfect one.
`run_detector_benchmark` currently reports that as containment 0.00% on all four,
which reads as the detector failing where there is in fact nothing to catch.
`opeval` excludes them and says so on stderr.

Small corpora are marked `n/r` rather than printed as `0.0%`. With 18 benign
trajectories, `floor(0.01 * 18) == 0`, so no threshold inside a 1% budget blocks
any benign and the cell says more about the sample than the detector. The same
applies to pAUC@1%: at n=18 the restricted region contains no ROC point, so the
standardized area is exactly 0.5 for a perfect scorer as readily as for a useless
one.

## Reproduce

```bash
python -m benchmarks.opeval --corpora redcode ipi_coding sleight agentharm
python -m benchmarks.opeval --seed 1          # and 2, 3, 4
pytest benchmarks/tests/test_opmetrics.py python/tests/test_target_density.py -q
```

## Next

1. Compose the target channel into `TrajectoryDetector` behind the conformal
   gate, combining channels as p-values rather than as a raw sum.
2. Re-run the `generalize` sweep with the density active and check whether the
   containment cliff at `up1` flattens. That is the load-bearing test of the
   whole thesis and it is one integration away.
3. Cohort baselines across sessions, which is what takes conformal off n=25.
4. Baseline-poisoning defenses: frozen within-session calibration,
   provenance-clean fitting, CUSUM on the baseline itself.
