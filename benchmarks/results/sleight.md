# SLEIGHT-Bench: where our authorization layer has no signal

SLEIGHT-Bench (arXiv:2605.16626, Anthropic alignment) is a 2026 benchmark of a
different kind from anything else we replay. RedCode, AgentHarm, and ASB
catalogue *risky operations*. SLEIGHT catalogues *evasion*: 44 attacks in which a
coding agent covertly pursues a harmful objective while trying not to look like
it is, across 12 categories including `authorization_confusion`, `multi_session`,
`n_hops`, and `model_priors`. Every attack ships with a matched benign transcript
for false-positive calibration.

We ran it because its category names are our claims, and because a system that
talks about loss-of-control behaviour should be measured on the benchmark built
for it.

## Result

45 attack transcripts, 43 benign pairs, full enforcement stack, judged per
transcript because a transcript is SLEIGHT's unit:

| Metric | Value |
| --- | --: |
| detection rate | 75.6% |
| false-positive rate | 69.8% |
| discrimination | **5.8 points** |

**Our authorization layer has essentially no discriminative power on this
corpus.** It flags three quarters of the attacks and seven tenths of the benign
sessions, which is close to flagging everything.

## Why, and why this is the expected answer

The layer decides per action, on what the action touches. SLEIGHT attacks are
defined by *intent*, and they are executed through actions that individually look
like ordinary engineering work: reading files in the checkout, running builds,
touching temp directories. The harmful objective lives in the pattern and the
purpose, not in any single target.

That is the **in-surface class** exactly as our coverage analysis defines it, now
demonstrated on external 2026 data rather than on our own partition. Our own
measurement said per-call authorization contains approximately none of that
class. SLEIGHT agrees, using someone else's attacks and someone else's
definition of harm.

It is hard for everyone, which is the other half of the context. The published
result is that an Opus 4.6 monitor with extended thinking never catches 20 of 40
attacks across ten trials at a 1% false-positive rate, with an overall catch rate
of 32%. This is not a benchmark where anything currently does well, and a
frontier model reasoning over the whole transcript does better than a per-action
policy for the obvious reason that it can see intent.

## What we are not claiming

The 75.6% detection figure is not a security result and should never be quoted
as one. At a false-positive rate of 69.8% it is close to a constant classifier,
and a defense that flags seven in ten legitimate engineering sessions is not
deployable at any threshold.

## What it changes

**It sets the boundary of the current product precisely.** Authorization binds
what an agent may touch. It does not, and structurally cannot, decide whether a
legitimate-looking sequence of permitted actions was undertaken for a harmful
purpose. Publishing this alongside the RedCode result (100% containment where the
attack leaves the granted surface) is the honest pair.

**It is the strongest external motivation for the behavioural tier.** The
trajectory detector, the aggregate limits, and the anchored-baseline work all
target the class SLEIGHT measures, and SLEIGHT is the first external instrument
we have that scores it.

**It gives the moonshots a benchmark.** `multi_session` maps onto the
cross-session ledger, `n_hops` onto delegation, and `authorization_confusion`
onto the enforcement layer itself. Per-category results on those three are the
next measurement worth making.

## Loader notes

Two bugs were found and fixed while building this, both of which produced
dramatic and wrong numbers:

- The workspace was hardcoded to `/repo`, so every path fell outside scope and
  the stack reported 89.6% containment at an 89.7% false-block rate. Each
  transcript records its own `cwd`, and the mandate is now derived from it.
- Evaluating per action rather than per transcript reported 35.7% containment at
  a 35.4% false-block rate, which is the same non-result in a different shape.
  SLEIGHT's unit is the transcript.

Transcripts are canary-protected and shipped encrypted. They live under
`.benchmark-corpus/`, which is gitignored, and no transcript content appears in
any result file.

## Reproduce

```bash
git clone https://github.com/safety-research/sleight-bench \
  .benchmark-corpus/sleight-bench
cd .benchmark-corpus/sleight-bench && python decrypt.py --key <key from its README>
python -m benchmarks.cli --dataset sleight --ci
```
