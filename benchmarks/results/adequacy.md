# Corpus adequacy: what our benchmarks can and cannot evaluate

STATUS: current

Produced by `python -m benchmarks.adequacy`. This is the prior question every
other results file in this directory skips: **is the corpus capable of exercising
the mechanism we are about to quote a number for?**

It has teeth because the answer is frequently no, and a corpus that cannot
exercise a mechanism does not return a low score. It returns a plausible one.

## The survey

| corpus | tasks | sess% | med len | ctx | obs/tgt | taint gap | per-action | trajectory | density | provenance |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | --- | --- |
| redcode | 768 | 7% | 1 | 0 | 3.4 | **−84%** | ok | NO | weak | NO |
| sleight | 43 | 100% | 12 | 43 | 2.0 | +1% | ok | ok | NO | NO |
| ipi_coding | 45 | 78% | 2 | 35 | 45.0 | +30% | ok | ok | ok | ok |
| agent_threat_bench | 24 | 25% | 1 | 6 | 2.4 | +0% | ok | NO | NO | NO |
| agentharm | 352 | 100% | 4 | 0 | 5.0 | +0% | ok | ok | ok | NO |
| toolemu | 116 | 97% | 5 | 0 | 4.8 | – | NO | NO | NO | NO |
| tau2 | 2545 | 96% | 6 | 0 | 285.4 | – | NO | NO | NO | NO |
| bfcl | 1927 | 22% | 1 | 0 | 4.7 | – | NO | NO | NO | NO |
| atif | 38 | 100% | 6 | 0 | 1.8 | – | NO | NO | NO | NO |
| asb | 51 | 100% | 42 | 51 | 5.1 | +10% | ok | ok | ok | NO |
| injecagent | 1054 | 100% | 3 | 1054 | 62.0 | +96% | ok | ok | ok | ok |

**Corpora able to evaluate each layer, of 11 surveyed:**

| layer | usable |
| --- | ---: |
| per-action authorization | **7** |
| trajectory / sequence | **5** |
| target density | **4** |
| provenance / taint | **2** |

And the provenance pair does not survive contact with the scoreboard's own
rules: `injecagent` is marked `SATURATED` and forbidden from pooled headlines,
which leaves **`ipi_coding`, 45 tasks**, as the only corpus in the programme that
can evaluate a provenance layer at all.

## The three findings that motivated the module

**1. Four corpora carry zero attack events.** tau2, BFCL, ToolEmu and ATIF
including the two largest and the only set of real agent sessions. Their "attack"
trajectory is the benign one unchanged, so every scorer including a perfect one
returns AUC 0.500. `run_detector_benchmark` reports that as containment 0.00% on
all four, which reads as four detector failures where there was nothing to catch.

**2. RedCode attack tasks are single-event.** 718 of them, median length 1, and
**zero** of them contain any benign event. Two consequences:

- A trajectory layer has no sequence to model, so any sequence result on RedCode
  is measuring a one-step "sequence".
- "Median steps-to-detect = 1", which `opeval.md` reported as early detection, is
  arithmetic. There is no second step to detect on. That claim is withdrawn.

**3. Provenance is inverted on RedCode, at −84%.** 83.7% of benign actions are
taint-derived against 0.0% of attack actions. The cause is (2): an attack
trajectory that begins cold never had a preceding read to taint it. A provenance
channel fit here would learn to flag **untainted** actions, would score well
doing it, and would be exactly backwards. The corpus rewards an inverted
detector.

This is the concrete form of flaw 6 in `docs/methodology_audit.md` ("the detector
taint eval would leak the label"), and it is worse than the flaw as written:
the leak is not aligned with the label, it is anti-aligned, so the resulting
detector would be confidently wrong rather than trivially right.

## Why this is the blocker, not a modelling problem

The per-action authorization layer is genuinely well covered, 7 corpora, and
that is the layer the shipped product enforces. Everything above it is thin:

- the **behavioural** claims rest on 5 corpora, of which 2 are saturated;
- the **density** claims on 4, only one of which clears the concentration floor;
- the **provenance** claims on 1 usable corpus of 45 tasks.

No amount of architecture changes those numbers. A better estimator evaluated on
a corpus that cannot exercise it produces a better-looking artifact, not a better
control. The path to a defensible behavioural claim runs through **data**: real
agent sessions, of realistic length, where the compromise occurs *inside* a
session that also contains legitimate work, with the injection point labelled.

That is a collection problem with a clear specification, and the specification
falls straight out of the columns above:

1. median session length well above 1 (RedCode: 1);
2. attack and benign events in the **same** session (RedCode: 0 of 718 tasks);
3. ≥5 observations per distinct target (RedCode: 3.4, ATIF: 1.8);
4. a taint gap that is positive and material (RedCode: −84%).

`benchmarks/adequacy.py` is the acceptance test for any corpus proposed to fill
that gap, and it runs before the corpus is wired rather than after a number has
been quoted from it.

## What should change in the existing programme

- **`run_detector_benchmark` must refuse a corpus with no attack events** rather
  than reporting 0.00% containment. Four of the corpora it is routinely run
  against are in that state. `opeval` already excludes them and says so on
  stderr; the older harness does not.
- **The steps-to-detect claim is withdrawn** on RedCode and any other corpus with
  median length 1. It should be reported only where `sess%` is high.
- **No provenance number should be quoted from RedCode**, in either direction.

## Reproduce

```bash
python -m benchmarks.adequacy
python -m benchmarks.adequacy --corpora redcode ipi_coding --json out.json
```
