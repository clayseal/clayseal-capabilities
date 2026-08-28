# Do the BPL failures cluster into mechanisms we have not built?

STATUS: current

```bash
python -m benchmarks.bpl_sweep --suite full --json /tmp/sweep.json
```

**This file prices nothing, and does not need to.** It analyses which scenarios
the suite fails and why the labels predict that; the containment and cost columns
both belong to the sweep it reads, `python -m benchmarks.bpl_sweep --suite full`,
where the gateway refuses 2 of 132 benign twins and loses work on none. Quoted
here so a reader arriving at this file alone does not take 53 of 132 as a result
with no price attached.

The question this set out to answer: 79 of 132 scenarios are not contained, and if
they decompose into a handful of missing mechanisms that is a roadmap. This is the
attempt, including the parts that did not work, because the parts that did not
work are the finding.

## Answer

**No pattern in the failures survives a base-rate control, and the reason is that
the suite's own labels predict the outcome with 97.7% accuracy.** The scenarios
that fail are the scenarios written as expected-to-fail. There is no residual for
a mechanism hypothesis to explain.

| scenario label | contained |
| --- | --- |
| `contain` | 50/50 |
| `partial` | 3/35 |
| `open` | 0/47, 97.5% upper bound 7.5% |

Every `contain`-labelled scenario is contained and almost nothing else is. That
is a strong statement about the suite and a weak one about the mechanism, and it
means this suite cannot answer the question it was interrogated with.

## What was tried, in order

### 1. Difficulty tags: no signal

`frontier`, `ultra`, `apex` and the rest are difficulty markers. They separate
hard from easy and say nothing about which mechanism is absent. Discarded.

### 2. Six mechanism hypotheses, from reading the scenarios

Reading the 79 failing prompts suggested six categories. They are recorded because
they are reasonable hypotheses, not because they are findings:

| hypothesis | example scenarios |
| --- | --- |
| the rule lives in a document fetched at runtime | `summary-strips-forbid`, `path-dependent-ceiling` |
| value has an economic identity a field name does not capture | `homomorphic-field-split`, `fx-stale-ceiling-arb`, `gross-exposure-net-mask` |
| the counterparty or object must be identified across differently named calls | `wash-trade-volume`, `bid-rotation-cartel`, `idempotency-key-collision` |
| the aggregate is over information rather than value | `adaptive-stats-reid`, `reidentifying-aggregate-posts`, `accumulated-scope-union` |
| an approval is bound to an object that is then amended | `approval-amendment-launder`, `attestation-false-clean` |
| authority changes mid-session on external events | `auto-stay-collect`, `kyc-expired-continue`, `authority-decay-chain` |

### 3. Base rates: two hypotheses die immediately

A category that appears as often in the contained scenarios as in the failures
explains nothing.

| pattern | in failures | in contained | lift |
| --- | ---: | ---: | ---: |
| runtime-fetched policy | 74/79 (94%) | 37/53 (70%) | 1.3x |
| economic identity of value | 9/79 (11%) | 2/53 (4%) | 3.0x |
| authority changes mid-session | 9/79 (11%) | 2/53 (4%) | 3.0x |
| aggregate over information | 3/79 (4%) | 0/53 | n/a |
| object / counterparty identity | 6/79 (8%) | 4/53 (8%) | 1.0x |
| approve-then-amend | 10/79 (13%) | 9/53 (17%) | 0.7x |

Counterparty identity has no lift at all. Approve-then-amend has lift **below**
one: those scenarios are contained more often than average, so it is a strength
being mistaken for a gap by anyone who reads only the failures. Both discarded.

### 4. Significance: the remaining three do not reach it

Two-sided Fisher exact, failures against contained:

| pattern | p |
| --- | ---: |
| aggregate over information | 0.27 |
| economic identity of value | 0.20 |
| authority changes mid-session | 0.20 |
| **runtime-fetched policy** | **0.0004** |

The three hypotheses that survived the base-rate check are indistinguishable from
noise at n=9. Only the one with the smallest lift is significant, because it is
the only one with the sample size to be.

### 5. The significant one, and why it is not real either

Splitting on it looked decisive:

| | clayseal contained | dataflow-taint contained |
| --- | --- | --- |
| rule is in the sealed grant | 76.2% (16/21) | 28.6% (6/21) |
| rule is fetched at runtime | 33.3% (37/111) | 32.4% (36/111) |

Read on its own that says the entire advantage over the baseline exists only
where the rule was compiled into the grant, which would be a sharp deployment
guideline.

It does not survive holding the label constant:

| label | rule in sealed grant | rule fetched at runtime |
| --- | --- | --- |
| `contain` | 100.0% (16/16) | 100.0% (34/34) |
| `partial` | 0/2, upper bound 84.2% | 9.1% (3/33) |
| `open` | 0/3, upper bound 70.8% | 0/44, upper bound 8.0% |

Within every label the difference vanishes. The sealed-grant scenarios are 76%
`contain`-labelled and the runtime-policy ones are 31%, and the whole apparent
effect is that composition. Simpson's paradox, and the only reason it was caught
is that the confound was checked before the result was written up.

## What this says about the suite

The generalization map compares measurement against label and reports zero
regressions and zero stale labels. That reads as validation and it is closer to a
tautology: with 97.7% label accuracy the map has almost no power to discover
anything. A label that predicts outcomes that precisely was written either after
measuring or by someone who knew the mechanism exactly, and neither makes it
evidence about generalization.

The labels were committed in the same commit as their scenarios and are never
read in the decision path, both checked. That rules out the crudest forms of
circularity and does not rule out this one.

## What would answer the question

The suite cannot find a mechanism gap because it has no scenarios that are
expected to be contained and are not. Three ways to get some:

1. **Held-out authoring.** Scenarios written by someone who has not seen the
   mechanism, with no `clayseal_expected` field, scored blind. The label is the
   problem, so remove it at authoring time rather than at scoring time.
2. **Promote the `partial` set.** 35 scenarios are labelled `partial` and 3 are
   contained. That is the only place in the suite where the label does not
   determine the answer, and it is where a real gap would first show.
3. **Adversarial search rather than curation.** `benchmarks/adaptive_stack.py`
   already puts the shipped gateway in front of a search that does not know the
   labels. A failure found there is a failure nobody wrote down in advance, which
   is the only kind that can surprise us.

Until one of those runs, the honest statement about coverage is the one the
containment table already makes: 40.2% of the suite, 76% of the part of it we
claim, and no evidence about which mechanism would move the rest.

## What did come out of it

Two defects, found by running the benchmarks rather than by analysing them:

- `task-scope` was the only gate of six that raised on adversarial input, on 5 of
  20 inputs (`None`, `0`, `[1]`, `{'a': 1}`, `True`), reported by
  `stress_gates.py` and unfixed. A gate that raises has not contained anything,
  it has crashed. Non-strings now normalise to a sentinel that matches no
  pattern, so they fail closed. Two of the five needed the guard OUTSIDE the
  `lru_cache`, because the decorator hashes its argument before the body runs.
- `stress_commit` reported `BASELINE=1`, a valid token failing to verify, because
  the fail-closed change made a replay store mandatory and the harness had not
  caught up.

Then a third, found by differential-fuzzing the two `path_matches_any`
implementations against each other, one in `path_matching.py` whose docstring
called itself "the canonical home" and one in `task_scope.py` that is the one
actually called. **3,298 disagreements in 39,403 comparisons**, and one class of
them was a deny-list bypass: with `denied_paths=["infra/prod/**"]` the live
matcher ALLOWED `infra\prod\web.tf`, reading the backslashes as filename
characters where the other read them as separators. A second bypass fell out of
the same investigation: `deny: ["infra/prod/**"]` did not deny `infra/prod`,
because `**` requires a segment after the slash, and most infrastructure tooling
takes a directory rather than a file.

Both are closed. An ambiguous path is now evaluated under every reading, denied
if any reading is denied and allowed only if every reading is allowed, and the
policy compiler closes a deny pattern over the directory it names. Neither was
found by reading the code; both came from running one matcher against the other
40,000 times.
