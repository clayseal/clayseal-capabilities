# Where the utility metric can mislead

The benchmarks report how much legitimate work a defended agent still completes.
That number is easy to read wrongly. This lists the ways it can be misleading,
most consequential first, so nobody tunes the system against a metric that is
measuring the wrong thing. The queued paired diagnostic
(benchmarks/live/diagnose_methodology.py) tests the first two directly; the rest
are framing issues to state, not bugs to fix in code.

## 1. We count STEP_UP as failure (measurement bug, likely large)

Our utility number treats any non-ALLOW as a lost task. But the design has three
outcomes: ALLOW, STEP_UP, DENY. A STEP_UP is a human confirmation that succeeds
in deployment; only a hard DENY of a benign action is an unrecoverable
false-positive. By collapsing them we report the pessimistic autonomous number
and hide the supervised one. If most of the clean-utility loss is step-ups, the
deployable utility is much closer to the oracle than it looks.

Diagnostic output: autonomous vs supervised success, and the DENY-vs-STEP-UP
split of every defense-caused loss.

## 2. We attribute every clean failure to the defense (no causal control)

Baseline clean utility with NO defense is only ~62%. So 38% of clean tasks fail
because the agent is bad, not because we blocked anything. Reporting "envelope 50%
vs baseline 62%" as a 12-point defense cost is only valid if the defense actually
flipped those tasks. It may have failed tasks that were already failing.

Diagnostic output: per-task paired comparison (none vs defense); only tasks that
succeeded under `none` and failed under the defense count as defense-caused, and
each is attributed to a DENY, a STEP_UP, or neither (the defense allowed
everything and the task still failed).

## 3. n is too small and variance is high (statistical validity)

n=8 clean, n=18-24 attack. Each clean task is worth 12.5%. The same envelope
config produced ASR of 55.6%, then 11.1%, then 12.5% across identical runs. Many
of our point comparisons are inside the noise band. Single-suite, single-run
deltas should not be read as real. The full multi-suite, two-model run in flight
partly addresses breadth, but the fix is more seeds and reported confidence, and
not over-reading any one cell.

## 4. Offline and live measure different things, quoted as if the same

The deterministic replay leaderboard shows 0% benign false-block, because it
replays ground-truth calls that pass by construction. The live run shows a real
utility loss. They are not contradictory: replay measures envelope correctness on
the minimal plan; live measures the envelope against a real agent's benign
variation (exploration, reordering, extra calls). We should always say which
question a number answers, and never cite the 0% replay false-block as if it were
the live false-positive rate.

## 5. We grade our own homework (synthetic attacks)

in-scope-burst, the adaptive fan-out and stealth variants, and fragmented-
overspend are our own constructions. They are reasonable and mechanism-derived,
but they are not wild attacks, and the detector and budget results are measured on
attacks we designed. This is acceptable for a mechanism claim but must be labeled,
and validated against external attack corpora where they exist.

## 6. The detector taint eval would leak the label

In the trajectory eval, benign trajectories are untainted by construction (only
ATTACK events carry the injection marker). Any taint-based detector would score
~100% at 0% false-block by reading the ground-truth label, not by real provenance.
We have not reported such a number, and must not until provenance comes from real
data.

## 7. AgentDojo utility may be the wrong metric for a graduated system

Deeper than a bug. AgentDojo utility is autonomous task completion. A security
layer that asks for confirmation before an irreversible action is behaving
correctly, not failing. The metric does not model the human-in-the-loop the design
assumes, so it structurally penalizes the exact behavior we want. Supervised
utility (flaw 1) is a partial fix, but the honest framing is that autonomous task
completion is a lower bound on the value of a system meant to run with a human on
the escalation path.

## 8. Deployability costs are unmodeled

The deployable envelope makes an extra LLM planner call per task to derive scope.
We do not count its latency or cost in "deployable". It is out of the enforcement
trust boundary (correct), but it is a real per-task overhead that a production
claim must account for.

## What the diagnostic will tell us, and what it will not

Will resolve: how much of the clean-utility loss is recoverable step-ups vs hard
denies (flaw 1), and how much is actually caused by the defense vs the agent
(flaw 2), with per-layer attribution, on banking and workspace.

Will not resolve: variance (flaw 3), the synthetic-attack question (flaw 5), and
the metric-appropriateness question (flaw 7). Those are addressed by more seeds,
external corpora, and an explicit supervised-utility framing, not by this run.
