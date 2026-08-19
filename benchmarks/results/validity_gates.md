# Validity gates, and what they say about us

STATUS: current

`python -m benchmarks.validity --results ... --meta ...`

Every checklist in this space is prose. The ML Reproducibility Checklist,
NERVE-ML and the responsible-AI frameworks are questionnaires a human answers,
and a 2026 survey of them puts the gap precisely: they "typically do not serve
as enforceable pre-deployment gates that translate governance principles into
explicit ship/no-ship decisions". A checklist that runs is a standard; a
checklist that is prose is an opinion.

## The taxonomy is borrowed on purpose

The ten pitfalls are **Arp et al., "Dos and Don'ts of Machine Learning in
Computer Security", USENIX Security 2022**, which surveyed 30 top-tier security
papers and found sampling bias, data snooping and lab-only evaluation endemic.

Inventing a taxonomy here would have been a mistake. A framework authored by the
same group that builds the defense is a framework shaped to the defense, and the
first thing a reviewer should ask of any self-published standard is who chose
the categories.

## Four of the ten cannot be automated, and say so

P1 sampling bias, P3 data snooping, P5 parameter selection and P9 lab-only
evaluation are judgement calls. Claiming to check them mechanically would be the
overclaiming this module exists to catch, so those gates **demand a declaration
and fail when one is absent**. An unanswered question is a finding.

## Every gate cites a defect it caught

A gate with no scalp is a guess. Each is here because it found something real in
this repository's own work, and `test_every_gate_cites_a_defect_it_caught`
enforces that.

| pitfall | what it caught here |
| --- | --- |
| P1 sampling bias | 4 of 11 corpora carried zero attack events; three headline numbers were computed on corpora that could not exercise the layer being scored |
| P2 label inaccuracy | 24 scenarios labelled `open` were contained; the labels had been calibrated against a verb-classifier bug |
| P3 data snooping | the adaptive harness never called `observe_corpus`, so velocity ran with a cap 6.4x tighter than an operator would set — in the direction that flatters |
| P4 trivial controls | a `deny-all` row caught a tie-handling bug scoring it 100% at 1% FPR, and a length leak scoring it AUC 1.000 |
| P5 parameter selection | sweeping alpha across a 20x range moved the false-block rate not at all on the only corpus with attacks |
| P6 baseline | reproductions of published defenses run and reported losing on a suite their authors did not design |
| P7 performance measure | of 35 scenarios contained only under a tight envelope, 30 also refused the benign twin |
| P8 base rate | a published table carried `0.0%` with a 95% CI of `[0.0, 0.0]`; the true one-sided bound at n=8 is 36.9% |
| P9 lab-only | every cumulative-authorization claim was measured in one process; four processes against a ceiling of 100 landed 400 |
| P10 threat model | every adaptive objective was defined through the negation of the defense under test, so the published 100% was definitional |

## Running it on ourselves

The first use was against our own headline sweep. It blocked on 8 of 10.

Three of those eight were bugs in the **gates**, and finding them that way is
the point — a checklist meets its own standard first:

- **`partial` labels cannot disagree.** Counting them as mismatches reported 36%
  label disagreement against a real rate of 25%.
- **A corpus label describes the system under test, not every condition.**
  Checking it against the baselines trebled the apparent disagreement; a
  baseline is *supposed* to fail a scenario labelled `contain`.
- **A deterministic replay may have n=1.** Demanding n>=5 confused "few samples"
  with "no randomness". The declaration is now required, so it cannot be claimed
  silently.

One was a genuine gap the gate was right about: the sweep had no `deny-all`
row. It has one now, and it scores 132/132 containment at 0/132 completion —
which is exactly why it has to be printed.

### Current verdict: BLOCKED on 2

| gate | status |
| --- | --- |
| P2 label inaccuracy | **FAIL** — 24 of 97 checkable labels disagree (25%) |
| P10 threat model | **FAIL** — one knowledge level, `scripted (author-written)` |
| the other eight | pass |

Both failures are real, both were already documented in
[bpl_full_sweep.md](bpl_full_sweep.md) and [invariance.md](invariance.md), and
the gates found them without being told. That is the only evidence worth having
that they work.

P10 is the honest one. The sweep replays attacks its own authors wrote. The
adaptive-evaluation literature's finding — static benchmarks made twelve in-band
defenses look strong until adaptive attacks broke them at over 90% — applies to
us, and the gate will keep saying so until there is a search rather than a
script.

## Using it on your own evaluation

`audit(cells, meta)` takes a list of per-cell outcomes and a declarations dict.
Nothing in it is specific to this repository, and the intended use includes
running it against us.

```bash
python -m benchmarks.validity \
  --results benchmarks/results/phase0/bpl_sweep.json \
  --meta    benchmarks/results/phase0/bpl_sweep_meta.json
```

---

# Both gates closed, and what closing them cost

## P10: an adaptive attacker, and it caught me overfitting

`benchmarks/adaptive_bpl.py` runs four nested knowledge levels over all 132
scenarios. Nested matters: a better-informed attacker must be able to do
everything a weaker one can, or a flat row is an artifact of which bag it drew
from. The first version was not nested and the monotonicity check caught it
immediately — `feedback` held 37 scenarios where `blind` held 36, which is not a
fact about any defense.

| family | scripted | blind | feedback | oracle |
| --- | ---: | ---: | ---: | ---: |
| aggregate | 82% | 80% | 80% | **76%** |
| confidentiality | 54% | 54% | 54% | 54% |
| escape | 63% | 61% | 61% | 61% |
| **ALL** | **67%** | 66% | 66% | **64%** |

Containment is monotone non-increasing in knowledge, as it must be. The
headline aggregate family moves most: **six points**.

**Four scenarios held under the scripted attack and broke under the oracle**,
and one of them is the important one.

### `contractor-scope-creep`: a fix fitted to a script

Earlier the same day, this scenario was closed by declaring
`identity_args=("person",)` — "grant each person once". It stopped the scripted
attack, which re-grants to the same Mira, and the sweep went green.

The adaptive attacker varied the person and walked through. The scenario's own
oracle is:

```python
if level == "read": granted_read = True
else: escapes.append("write-grant")
```

**Any** write-level grant is the violation, to anyone. So the mandate answered
the script rather than the objective, and it was chosen because it made the test
pass. That is benchmark-fitting, in this repository, caught within hours by the
gate that exists to catch it.

The fix was reverted rather than replaced. The correct mandate constrains the
`level` **argument**, and this system cannot express that — `authorized_arg_hashes`
binds whole argument sets by hash, so "any person, `level=read` only" would mean
enumerating every person. The scenario is labelled `open` again and the gap is
recorded in `make_broker`.

Adding an argument-value constraint now, in direct response to a benchmark
scenario, would repeat the mistake at a larger scale. It goes on the list as a
capability gap with a named use case, not as tonight's patch.

The contrast is `retry-storm-double-effect`, which holds at every level: its
objective *is* a duplicate effect, so `identity_args=("invoice",)` expresses the
rule rather than approximating it. Same mechanism, and the difference is whether
the mandate says what the policy means.

## P2: labels re-derived, and the gate now demands provenance

24 stale `open` labels were re-derived to `contain` after the verb-classifier
defect was fixed; one moved the other way the same day, above.

Agreement I manufactured is not evidence, so the gate now requires
`labels_provenance` and prints it beside the verdict. A label re-derived from
the run it is compared against is a **regression guard**, not an independent
prediction, and a checklist that cannot tell those apart is one a project
satisfies by editing its own answer key.

## Verdict

**10 of 10 gates pass.** The two that were failing are closed by measurement and
a retraction, not by adjusting the thresholds.
