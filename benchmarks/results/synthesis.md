# Closing the data gap with data already in the repo

STATUS: current

[adequacy.md](adequacy.md) found the blocker: of 11 corpora, 7 can evaluate the
per-action layer, 5 the trajectory layer, 4 the density, and **1** (after
saturation rules) the provenance layer. Every behavioural claim rested on corpora
built to test something else.

The gap turns out to be closeable without collecting anything. The repo holds
both halves and they had never been combined:

- **Attack corpora with no sessions.** RedCode: 718 attack tasks, median length
  1, zero containing a benign event.
- **Session corpora with no attacks.** tau2, BFCL, ToolEmu, ATIF: thousands of
  real multi-step sessions, zero attack events.

`benchmarks/adversarial` already synthesizes attack variants from benign tasks.
Pointed at the second group it produces exactly the shape the adequacy spec asks
for, an injection landing inside a session that also contains legitimate work.

## Adequacy of the synthesized corpora

Four attack classes (`path-exfiltration`, `unauthorized-tool`,
`action-escalation`, `goal-drift`) over the first 400 tasks of each base corpus.

| corpus | tasks | sess% | med | ctx | obs/tgt | taint gap | len AUC | per-action | trajectory | density | provenance |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | --- | --- |
| tau2+synth | 1300 | 100% | 5 | 1300 | 155.2 | +17% | 0.632 | ok | ok | ok | **ok** |
| atif+synth | 151 | 100% | 7 | 151 | 7.2 | +14% | 0.641 | ok | ok | ok | **ok** |
| toolemu+synth | 464 | 100% | 6 | 464 | 19.1 | +21% | 0.681 | ok | ok | ok | **ok** |
| bfcl+synth | 1335 | 100% | 2 | 1335 | 10.0 | +54% | **1.000** | NO | NO | NO | NO |

Three corpora now clear all four layers, including provenance, which previously
had one usable corpus of 45 tasks. The taint gap flips from RedCode's **−84%** to
**+14% to +21%**, because an injection landing mid-session *is* derived from
content that arrived after the goal was sealed, which is what the taint flag was
always supposed to mean.

## The leak the controls caught, and the check that now catches it earlier

`bfcl+synth` passed all four layers on the first run of `adequacy.py`. It is
nonetheless unusable, and the `position` and `length` control rows in `opeval`
said so immediately: **AUC 1.000, det@1% 100%, on both.**

The cause is structural. A synthesized variant is `benign_events +
attack_events`, so an attack trajectory is strictly longer than the benign
trajectory it is scored against. On a corpus of long sessions that difference is
noise; on BFCL, whose median task is 1 event, it *is* the label.

`adequacy.py` now computes the length shortcut directly, the AUC of trajectory
length as a classifier, which needs no model at all, and a corpus scoring ≥0.75
is marked unusable on **every** layer at once, because there is no point asking
whether a density can be evaluated where counting actions already scores 1.000.
tau2, ATIF and ToolEmu sit at 0.63–0.68 and pass.

This is the second time in this work that a control row found a defect the
purpose-built check missed. The pattern is worth naming: **a diagnostic written
by the same person who wrote the mechanism inherits their blind spots; a control
that is deliberately stupid does not.**

## What the channels do on an adequate corpus

tau2+synth, threshold pinned to a 1% benign block rate.

| scorer | AUC | det@1% | det@5% | steps-to-detect |
| --- | ---: | ---: | ---: | ---: |
| deny-all | 0.500 | 0.0% | 0.0% | – |
| position | 0.571 | 0.0% | 0.0% | – |
| length | 0.624 | 0.8% | 5.8% | – |
| ngram | 0.972 | **54.2%** | 79.2% | 6 |
| target | 0.900 | **68.5%** | 69.6% | 5 |
| ngram+target | 0.972 | 68.3% | **82.5%** | 5 |
| conformal-combo | 0.963 | 48.5% | 78.7% | 6 |
| target\|taint | 0.891 | 48.7% | 70.4% | 5 |

Three things worth reading here.

**The channels work when the corpus can exercise them.** The n-gram scorer, which
is *below chance* on RedCode (AUC 0.425), reaches 0.972 here. That is the
adequacy argument in one row: its RedCode number measured the corpus, not the
scorer.

**Fusion helps here and hurt on RedCode.** `ngram+target` is the best row at a 5%
budget (82.5%). The earlier finding that summing channels hurts was true and
specific, it holds when one channel carries negative information, not in
general. Neither result generalizes without the other.

**Steps-to-detect is finally a real measurement**: 5–6 actions into the
trajectory, on sessions of median length 5. On RedCode the same column read 1,
which was arithmetic.

## The provenance channel: built, measured, and it does not help

`ProvenanceStratifiedScorer` calibrates the target density separately for
taint-derived and clean actions, using the `MondrianConformal` primitive already
in the monitor with taint as its bucket. The argument was a conjunction: novel
targets are common, taint-derived actions are common, both at once is rare.

It scores **48.7%** at a 1% budget against the plain target channel's **68.5%**.
The conjunction did not pay.

The reason is visible in the taint gap itself. At +17%, tainted benign actions
are numerous, so the tainted stratum's benign reference is broad, and scoring a
tainted attack against broad tainted-benign traffic *absorbs* the signal rather
than sharpening it. Stratification helps when the stratum is rare and the
reference is tight; here it is neither.

That is an honest negative on a hypothesis stated in advance, and it is the third
mechanism in this line of work to be measured and set aside. It is reported
rather than tuned into a win: a weighting fitted until the number improved would
be exactly the eval-fitting this programme exists to remove.

## Caveats, unhedged

- **These attacks are ours.** Flaw 5 in `docs/methodology_audit.md` applies in
  full. The synthesis is mechanism-derived and reasonable, and it is not a wild
  attack. It is a better *substrate* than what existed: it can exercise layers
  nothing else could, and it is not evidence about real adversaries.
- **One length shortcut is measured and bounded, not eliminated.** 0.63–0.68 AUC
  from length alone survives on the passing corpora. Every number above is
  partly that, and the `length` row quantifies how much: 0.8% detection at a 1%
  budget, so little at the operating point that matters.
- **No adaptive adversary has been run against these.** The density's collapse
  under mimicry (`density_sweep.md`) was only found by attacking it. Nothing here
  has been attacked yet, and until it has, these are fixed-attack numbers.

## Reproduce

```bash
python -m benchmarks.adequacy                      # the base corpora
python -c "from benchmarks.datasets.base import get_loader; \
from benchmarks.adversarial.attacks import synthesize; \
import benchmarks.adequacy as A; \
t=list(get_loader('tau2').load())[:400]; \
s=[v.task for v in synthesize(t, classes=['path-exfiltration','unauthorized-tool','action-escalation','goal-drift'], seed=0)]; \
p=A.profile('tau2+synth', s); print(A.render([(p, A.verdicts(p))]))"
```
