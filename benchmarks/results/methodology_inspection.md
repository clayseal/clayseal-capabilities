# Methodology inspection

STATUS: current

```bash
python -m benchmarks.bpl_sweep --suite full
python -m benchmarks.check_claims
python -m benchmarks.verify_results
```

Five questions a reviewer asks about a benchmark whose authors also built the
system being measured. Each answered by measurement rather than by assertion.

## 1. Is the interval a property of the data or of the seed?

Every bootstrap in the sweep is seeded 7. Re-run across 40 seeds:

| quantity | mean | sd | range |
| --- | ---: | ---: | --- |
| cluster-robust rate, lower bound | 0.243 | 0.0025 | [0.236, 0.247] |
| cluster-robust rate, upper bound | 0.574 | 0.0038 | [0.566, 0.582] |
| paired difference, lower bound | 0.187 | 0.0036 | [0.182, 0.189] |
| paired difference, upper bound | 0.376 | 0.0037 | [0.371, 0.379] |

**The difference interval never crosses zero across 40 seeds**, minimum lower
bound 0.182. Seed choice moves a bound by well under a percentage point, so the
published interval is a property of the data.

## 2. Is the `per-call` baseline a strawman?

It scores nothing on the joint metric across all 132 scenarios, which is exactly
what a crippled baseline looks like. It is not crippled, and the arithmetic says
why:

| condition | contained | completed | benign twins refused | gate errored |
| --- | ---: | ---: | ---: | ---: |
| none | 0/132 | 132/132 | 0 | 0 |
| **per-call** | **0/132** | **132/132** | **0** | 0 |
| dataflow taint | 42/132 | 83/132 | 49 | 0 |
| clayseal | 54/132 | 130/132 | 2 | 0 |
| deny-all | 132/132 | 0/132 | 132 | 0 |

`per-call` completes everything and refuses nothing, so its zero on the
conjunction is forced by "allows every in-scope call, holds no state" rather than
by a handicap. It is **given the policy**: it reads `scenario.policy.of_kind
("scope")` and enforces the scope rule. It simply has nowhere to put a running
total.

**It is behaviourally identical to `none` on all 132**, and that is the strongest
form of the architectural claim rather than a bug in the harness. Every violating
script in this suite is in scope by construction, because that is what makes a
scenario a business-process-logic scenario: every individual call is authorized.
A per-call gate handed the rule therefore behaves exactly as no gate at all. Two
rows that match is the result.

## 3. Are the baselines named honestly?

Yes, and this was already handled before the inspection. `per-call` and
`dataflow-taint` were once called `progent` and `camel`, and were renamed because
they are roughly ten-line reproductions of the architectural CLASS each belongs
to and naming them after published work invites the only review comment that
matters. `drift` and `authgraph` keep their names because they are mechanism
reproductions built from the published designs and cite them, and both are
labelled "-shaped".

The claim needs the class, not the name:

> A defense with no cross-call state cannot enforce an aggregate constraint,
> because the constraint is not a property of any single call.

That is checkable by inspection and does not rest on how faithfully anyone
reimplemented anyone.

## 4. Is `deny-all` a real control, or decoration?

Real, and it wins the containment column outright at 132/132. A containment
number that does not beat it is not a measurement. It scores nothing on the
conjunction, which is the property that makes the conjunction the column to
quote: **no degenerate policy can take it.** `none` takes completion, `deny-all`
takes containment, and both score zero on the metric that requires both.

## 5. Can the evaluation surprise its authors?

Partly, and the bound is measured rather than argued.

The suite's `clayseal_expected` labels predict containment with 97.7% accuracy,
so no analysis that reads a label can discover anything. Two that read none:

- **Leave one authoring batch out.** Held-out batches do not score
  systematically worse than the rest, so there is no evidence of fitting to
  individual scenarios. Held-out rates run from nothing to 100%, sd 0.344, which
  is the justification for the cluster-robust interval.
- **Split on what the grant configures.** 83.3% [69.4%, 91.7%] where the grant
  expresses the constraint as a budget against 18.9% [12.1%, 28.2%] where it does
  not, Fisher exact p < 1e-11. Configuration alone predicts the outcome 81.8% of
  the time; the label predicts 98.5%. So the bulk of what the label knows is a
  fact about the grant any reader can recover, and the residual 17 points is the
  part that cannot be checked.
- **Adversarial search**, which reads neither labels nor scenario files, and which
  independently reproduced the published `in-scope-exfiltration` gap while finding
  one thing the curated suite does not report
  ([adaptive_stack_labelfree.md](adaptive_stack_labelfree.md)).

What remains is what every curated benchmark has: a scenario is only in the suite
if someone wrote it.

## Gaps this inspection leaves open

Stated rather than closed, because naming them is worth more than a partial fix.

- **The deterministic sweep is not pre-registered.** `core/reporting.py` has
  `PreRegistration` with design hashing and a `publishable()` gate that
  mechanically refuses a cell with no denominator, a bare zero, fewer than five
  seeds, no prereg hash or an unverified model identity. The sweep uses neither.
  It is deterministic, so seeds and sampling do not apply, but the design was
  still not declared before it was run.
- **`progress` is scenario-defined.** The friction split between "work lost" and
  "work done anyway" leans on it, and a progress function insensitive to the
  blocked call would report full progress for work that did not happen. Reported
  as the optimistic bound with the strict column beside it.
- **Multiple comparisons are corrected within a table, not across the tree.**
  Holm is applied across the four conditions the sweep compares. Eighty results
  files exist and a reader could scan any cell in any of them.
- **Two scenario grants were changed after their failures were inspected.**
  Disclosed with both numbers and a subtraction path in
  [grant_changes_2026_08.md](grant_changes_2026_08.md).

## What was fixed by this inspection

Nothing in the statistics needed fixing. The inspection did surface that
`per-call` matching `none` exactly should be **reported as a result** rather than
left to look like a harness bug, which is now stated above and is the cleanest
version of the architectural claim in the whole evaluation.
