# The safety/usefulness frontier

Every earlier result here was one operating point. This is the curve. Reproduce
with `python -m benchmarks.live.frontier --suite banking`.

Three axes, always together: attack success (safety), clean utility
(usefulness), and **interruptions per task** (the attention the protocol
spends). The third is what the AI-control literature insists on and what we had
been giving away for free.

## banking, gpt-4o-mini, 6 user x 3 injection per configuration

| Configuration | ASR | clean utility | friction/task | |
| --- | --: | --: | --: | --- |
| none | 66.7% | 50.0% | 0.00 | frontier (the do-nothing corner) |
| floor | 44.4% | 33.3% | 1.17 | dominated |
| envelope | 33.3% | 16.7% | 1.83 | dominated |
| **envelope-taint** | **0.0%** | **33.3%** | **0.83** | **frontier** |
| envelope-taint-graduated | 0.0% | 16.7% | **4.17** | dominated |
| envelope-taint-defer | 0.0% | 16.7% | 2.50 | dominated |
| envelope-taint-deferallow | 0.0% | 33.3% | 0.83 | frontier (but see below) |
| envelope-taint-graduated-audit1 | 0.0% | 16.7% | 1.67 | dominated |
| envelope-taint-graduated-audit3 | 0.0% | 16.7% | 4.33 | dominated |

Three of nine configurations are on the frontier. Six are strictly worse than
`envelope-taint` on all three axes at once, which is a useful thing to know
about six configurations we have variously described as improvements.

## workspace, same protocol

| Configuration | ASR | clean utility | utility under attack | friction/task | |
| --- | --: | --: | --: | --: | --- |
| none | 83.3% | 100.0% | 27.8% | 0.00 | frontier (do-nothing corner) |
| floor | 0.0% | 100.0% | 88.9% | 4.17 | dominated |
| envelope | 0.0% | 100.0% | 88.9% | 4.50 | dominated |
| **envelope-taint** | **0.0%** | **100.0%** | 83.3% | **1.50** | **frontier** |
| envelope-taint-graduated | 0.0% | 100.0% | 94.4% | 6.00 | dominated |
| envelope-taint-defer | 0.0% | 100.0% | 88.9% | 2.00 | dominated |
| envelope-taint-deferallow | 0.0% | 100.0% | 88.9% | 2.33 | dominated |
| ...-graduated-audit1 | 0.0% | 100.0% | 88.9% | 2.50 | dominated |
| ...-graduated-audit3 | 0.0% | 100.0% | 88.9% | 4.17 | dominated |

**This is the strongest single operating point in the repo: 0.0% ASR at 100%
clean utility, matching the undefended baseline exactly, for 1.50 interruptions
per task.** Attack success falls from 83.3% to zero and utility under attack
rises from 27.8% to 83.3%, at no measured cost to clean work.

Eight of nine configurations are dominated, and every one of them is dominated
on the attention axis, since they all reach 0.0% ASR at 100% utility and differ
only in how often they interrupt. Without that third axis this table would be
eight-way tied and useless.

## The variance finding, which cuts against our own retraction

Compare `deferallow` on workspace across two runs of the same configuration:

| Run | workspace `deferallow` ASR |
| --- | --: |
| validation sweep | **27.8%** |
| frontier sweep | **0.0%** |

Same code, same suite, same model, same attack, n=18 both times. **ASR itself
has run-to-run variance wide enough to flip a shipping decision.**

We had been treating utility as the noisy axis and ASR as solid. It is not. The
`deferallow` retraction still stands, because travel independently showed 5.6%
to 27.8% and nothing since has contradicted that, but the workspace half of the
evidence is now one result for and one against. The retraction rests on travel
alone.

More importantly, this applies to **every 0% ASR in this repository**, including
the ones we are proudest of. A single n=18 run showing 0.0% is consistent with a
true rate meaningfully above zero. The Wilson upper bound on 0 of 18 is about
18%, which is not a rounding error.

The fix is the one already prioritised in [../../notes/above_sota.md](../../notes/above_sota.md):
repeat every sweep and report the spread. `frontier.py --repeats N` now does
this. No security claim should be published from a single sweep, ours included.

## What the curve says that a point could not

**1. `envelope-taint` is the operating point to ship on this suite.** 0% ASR at
33.3% clean utility for 0.83 interruptions per task. Nothing beats it except by
giving up safety entirely.

**2. Graduated response is dominated, and pricing attention is what shows it.**
`envelope-taint-graduated` reaches the same 0% ASR and costs **4.17
interruptions per task**, five times as many, for *half* the clean utility.
Measured on the two axes we used to report, it looks like a tie. Measured on
three, it is strictly worse. That is the entire argument for the audit budget,
visible in one row.

**3. The audit budget does what it was built to do.** Capping at one
interruption takes friction from 4.17 to 1.67 with ASR unchanged at 0%. It
converts an unbounded attention cost into a bounded one, which is both a UX
property and a security property: a step-up policy is attackable by exhaustion,
and an unbounded step-up count is an unbounded attack surface.

**4. `deferallow` sits on the banking frontier and must still not ship.** This
is the honest tension in the chart. On banking it matches `envelope-taint`
exactly. On travel and workspace it takes ASR to 27.8%
([denial_diagnosis.md](denial_diagnosis.md)). A frontier drawn on one suite
would recommend it. **A per-suite frontier is a per-suite recommendation**, and
the deployment decision has to be the intersection across suites, not the union.

## What it does not say

- n=18 per configuration. The 33.3% and 16.7% utility figures are 6 and 3 tasks
  respectively, and the same configuration has produced both across runs. Treat
  utility differences under ~25 points as unresolved.
- One model, one attack. The frontier's *shape* is the claim, not the exact
  coordinates.
- `none` appears on the frontier because nothing dominates the do-nothing
  corner: it has the best utility and the worst safety. That is correct and it
  is worth stating, because a frontier that excluded it would be assuming its
  own conclusion.
