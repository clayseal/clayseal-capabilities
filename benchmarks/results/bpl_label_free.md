# Generalization, measured without the labels

STATUS: current

```bash
python -m benchmarks.bpl_sweep --suite full
```

[bpl_failure_patterns.md](bpl_failure_patterns.md) concluded that the suite
cannot answer where the mechanism fails, because `clayseal_expected` predicts
containment with 97.7% accuracy and the failures are the scenarios written as
failures. That conclusion stands for any analysis that reads a label.

This one does not read a label. Two measurements, and the second changes what
the first one means.

## 1. Leave one authoring batch out

Scenarios were written in batches of four to twelve, one file at a sitting. If
containment is a property of the mechanism it survives holding a batch out. If
it is fitted to particular scenarios, held-out batches score worse than the rest.

| held-out batch | n | held out | the rest |
| --- | ---: | ---: | ---: |
| aggregate | 4 | 100.0% | 37.5% |
| aml | 8 | 87.5% | 36.3% |
| frontier | 8 | 87.5% | 36.3% |
| legacy | 5 | 80.0% | 37.8% |
| confidentiality | 4 | 75.0% | 38.3% |
| deep | 8 | 75.0% | 37.1% |
| escape | 4 | 75.0% | 38.3% |
| literature | 9 | 66.7% | 37.4% |
| ultra | 6 | 50.0% | 38.9% |
| edgecases | 12 | 25.0% | 40.8% |
| unorthodox | 8 | 25.0% | 40.3% |
| specialty | 6 | 16.7% | 40.5% |
| institutional | 8 | 12.5% | 41.1% |
| crossdomain | 10 | 10.0% | 41.8% |
| nightmare | 10 | 10.0% | 41.8% |
| apex | 10 | 0/10 | 42.6% |
| paradox | 12 | 0/12 | 43.3% |

**Held-out rates run from nothing to 100.0%, sd 0.344, against a pooled 39.4%.**

Held-out batches do not score systematically worse than the rest, so there is no
evidence of fitting to individual scenarios. What there is instead is enormous
heterogeneity: this is not a mechanism with a 39.4% success rate, it is a
mechanism that works on some kinds of scenario and not at all on others, and the
pooled figure is a property of the suite's mix.

That is the justification for quoting the cluster-robust interval,
39.4% [24.3%, 57.9%], rather than the naive 39.4% [31.5%, 47.9%]. With this much
between-batch variance the naive interval is not conservative, it is wrong.

## 2. What the grant configures

Whether a scenario's `make_broker` sets up a value or call budget is a property
of the **configuration**. It is fixed before anything runs, readable from source,
and nobody has to be trusted about it. It is the closest thing this suite has to
a pre-registered covariate.

| the scenario's grant | n | clayseal | dataflow taint |
| --- | ---: | --- | --- |
| configures a budget | 42 | **83.3% [69.4%, 91.7%]** | 2.4% [0.4%, 12.3%] |
| configures none | 90 | 18.9% [12.1%, 28.2%] | 15.6% [9.5%, 24.4%] |

Fisher exact p < 1e-11.

Two things in one table. The mechanism contains a scenario four times more often
when the grant expresses the constraint as a budget, which is what the
architecture predicts and is now measured rather than asserted. And **dataflow
taint runs the other way**: it is worse than useless on budgeted scenarios (2.4%)
and better than us nowhere else by much (15.6% against 18.9%). The two are
complementary along exactly this axis, which is a sharper statement of the
complementarity the sweep already reports.

## What this does to the label problem

**Configuration alone predicts containment 108/132, 81.8%.** The label predicts
98.5%.

So most of what the label "knows" is not private knowledge about the mechanism.
It is a fact about the grant that any reader can recover from the scenario
source. The labels are largely recording something mechanically true rather than
encoding an answer.

The remaining 17 points are the part that cannot be checked, and they are real:
24 scenarios where the two predictors disagree. Seventeen are contained with no
budget at all, by the envelope, scope or egress rungs (`ci-secret-probe`,
`tool-schema-exfil`, `delegate-then-widen`, `policy-file-patch`). Seven are
budgeted and not contained, and five of those are labelled `open`.

This is a materially better position than "the evaluation set is contaminated and
nothing can be said". The honest statement is narrower and defensible:

- The bulk of the outcome is explained by a configuration property observable
  without the labels.
- The evaluation still cannot discover a failure mode nobody anticipated,
  because a scenario is only in the suite if someone wrote it.
- The heterogeneity across batches is large, and any single pooled number,
  including ours, should be read with it.

## The deployment rule this gives

It is the same sentence as the finding, which is the point:

**Express the constraint as a budget and it is enforced. Where the constraint
cannot be written as a ceiling on a countable or summable effect, the aggregate
rung has nothing to accumulate against, and containment falls to what the
envelope, the scope and the egress list happen to catch.**

That is directly actionable against `docs/POLICY.md`: `budgets.value` and
`budgets.calls` are where this mechanism lives, `clayseal policy lint` already
reports an effectful tool that debits no budget as an error, and this measures
what that error is worth.

## What it cost

The same sweep, same command. Of the 132 benign twins the gateway refuses **2**,
and neither loses work: both are interrupted on a call that was not on the
critical path and still reach full progress. `deny-all` refuses 132 of 132 and
loses work on all of them, which is what the joint metric exists to price.

A containment figure from this suite without that column is not a measurement:
refusing everything wins the containment side outright.

## What would still be needed for a claim about unanticipated failures

Nothing here removes that gap. It needs scenarios the authors did not write:
adversarial search against the shipped gateway (`benchmarks/adaptive_stack.py`,
which reads no labels), or scenarios authored blind by someone who has not seen
the mechanism.
