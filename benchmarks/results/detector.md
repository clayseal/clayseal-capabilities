# Trajectory detector: the uncontested class, measured without the label

The goal-conditional trajectory detector is meant to catch the class even the
budget rung cannot: fully-authorized aggregates like in-scope-burst (an
authorized read repeated into a scanning/exfil burst), where every action passes
every per-call check and the sequence is the attack. This is the frontier the
research map found empty. Here is what it actually does today, measured with the
detector blind to the ground-truth label.

## Provenance is data-flow derived, not label derived

Earlier versions of this benchmark tainted an action iff it was the injected
(ATTACK-labeled) event, then hard-blocked any tainted consequential action. That
made the taint tier read the answer key: goal-drift and connector-substitution
scored 100% because the label, not the behaviour, marked them. That is fixed. In
`benchmarks/core/detector_eval.py`, an action is now marked driven-by-untrusted-
context purely from data flow (the trajectory has already crossed an external
read earlier in the stream), computed identically for benign and attack events;
the ATTACK label is never consulted to taint an action or to decide a block. The
sealed goal's expected verbs likewise come from the user's own benign steps, not
from the injected events. Taint hard-blocks only when the untrusted-driven action
also leaves the typed envelope, untrusted-driven AND off-goal, the injection
shape. The numbers below are what the detector earns under that rule.

## The setup is right: the per-call ladder is totally blind

On the aggregate class, in-scope-burst containment across the entire enforcement
ladder:

| Engine | in-scope-burst containment |
|---|--:|
| tool-allowlist through task-scope+binding+budget | **0%** |
| deny-all | 100% (at 100% false-block) |

Every per-call rung, including the stateful budget rung, scores 0. Only a
trajectory-level detector can catch this class at all. That part of the thesis
holds by construction.

## What the label-blind detector earns

Fit the goal-conditional detector (ngram scorer, conformal alpha=0.05) on benign
trajectories from a shuffled train split; measure per-class containment on
held-out attack variants and false-block on held-out benign. The detector's own
job is in-scope-burst; goal-drift and connector-substitution leave the authorized
surface and are the enforcement floor's job (next section).

| corpus | n_train | in-scope-burst | benign false-block |
|---|--:|--:|--:|
| bfcl (real function-calling, 1200 tasks) | 720 | **100.0%** | **0.0%** |
| tau2 (heterogeneous dual-control, 1200 tasks) | 720 | 66.7% | 5.4% |
| atif (22 long benign) | 22 | 0% (abstains) | 0% |

The headline is honest and it is strong: on bfcl the detector contains **100
percent of in-scope-burst at a 0 percent observed false-alarm rate** on the
fully-authorized aggregate class the entire per-call ladder scores 0 on. On tau2,
whose benign corridor is loose (heterogeneous dual-control), the same detector
gets 66.7% at a 5.4% false-alarm rate, weaker, and honestly so. atif is too
small to calibrate a corridor, so the detector abstains (0 containment, 0
false-block) rather than over-flag.

## goal-drift and connector-substitution are the floor's job, not the detector's

These two classes do not stay inside the authorized surface: goal-drift calls a
tool the goal never granted (`send_external`) and connector-substitution swaps the
target to a look-alike resource outside the goal's allow-list. The per-action
enforcement floor (task-scope + binding + budget) contains both at 100% on both
corpora:

| class | floor containment (bfcl / tau2) | detector alone (bfcl / tau2) |
|---|--:|--:|
| goal-drift | 100% / 100% | 100% / 100% |
| connector-substitution | 100% / 100% | 31% / 89% |

The floor catches them because they violate a per-action scope, which is exactly
what a per-action check is for. The detector also catches goal-drift (the novel
tool is structurally surprising) but is not a reliable catcher of
connector-substitution (a same-tool, same-verb resource swap is not a trajectory-
shape anomaly). The layered system contains both at 100% via the floor. The
earlier "detector contains these at 100%" claim was the label leak; the correct
statement is that the floor owns them and the detector owns in-scope-burst.

## The false-alarm bound: per-tier conformal, honestly stated

Each hard-blocking tier, the learned trajectory scorer, the CUSUM drift tier, and
the path-envelope, is a proper per-bucket (Mondrian) split-conformal test, so
each is individually bounded at alpha. They fire on different shapes (novel
bigrams, sustained elevation, corridor departure), so their benign flags barely
overlap and the empirical UNION false-alarm rate stays near alpha; the honest
worst-case union bound is k*alpha. AML informs reasons but does not carry a
conformal budget (its aggregate-volume job is the floor's budget rung). The bound
responds to alpha as a conformal control must:

| corpus | alpha 0.01 | 0.05 | 0.10 | 0.20 |
|---|--:|--:|--:|--:|
| bfcl false-block | 0.0% | 0.0% | 0.0% | 11.2% |
| bfcl in-scope-burst | 89.1% | 100% | 100% | 100% |
| tau2 false-block | 0.0% | 5.4% | 10.4% | 23.3% |
| tau2 in-scope-burst | 0% | 66.7% | 86.7% | 93.3% |

False-block tracks alpha monotonically and sits at or below alpha at 0.05 on both
corpora. A single combined statistic could reclaim the per-tier split for more
power at a fixed alpha, but calibrating its threshold is data-fragile on
heterogeneous corpora (it overshot alpha on bfcl in testing), whereas per-tier
conformal control is robust; that is the deliberate trade.

## Adaptive robustness: the honest frontier (corpus-dependent)

The field's central critique is static-only evaluation, so: a defense-aware
aggregate attacker that shapes the burst to stay in-corridor. The result is the
same split the numbers above imply. Where benign is homogeneous (bfcl), the
corridor is tight and the attacker cannot both stay inside it and move a large
aggregate, containment stays high. Where benign is heterogeneous (tau2), the
corridor is loose, so a small aggregate fits inside natural variation and shape
alone cannot catch it; containment degrades toward the false-alarm floor. That
residual is not a shape problem to tune away, it is the province of a different
signal: provenance / taint catches an untrusted-driven read regardless of volume.
Shape and taint are complementary, and the honest claim is shape-robust on
homogeneous workloads, taint-dependent on heterogeneous ones.

## Honest standing of the claim

- The deterministic aggregate enforcement (the budget rung, sub-threshold
  splitting) is proven on real data. See bpl_aggregate.md.
- The learned goal-conditional trajectory detector, measured blind to the label,
  contains **100 percent of in-scope-burst at 0 percent false-alarm on bfcl**, a
  class the per-call ladder cannot touch. On a homogeneous corpus this is a
  genuine result for a threat shape the published field only exposes and never
  defends.
- The honest boundary: on a heterogeneous corpus (tau2) containment is 66.7% at
  alpha, and a defense-aware attacker pushes a small aggregate toward the
  false-alarm floor. Shape alone cannot catch it; that residual belongs to
  provenance / taint (origin, not volume).
- goal-drift and connector-substitution are contained by the per-action floor at
  100%, not by the detector; crediting the detector for them was the label leak,
  now removed.
- The remaining data limit is corpus size on small suites (atif/agentdojo
  abstain), correctly sequenced after calibration.

## Next

1. Scale the benign corpus on the thin suites (ATIF-scale, ultimately iVisor
   syscall/tool trajectory capture) so small buckets stop abstaining.
2. Add the provenance/taint signal on the tau2-style stealth residual, which
   shape misses, and report shape+taint jointly.
3. Report containment on the full class set with the defense-aware adaptive
   aggregate attacker on the deployable path (not the oracle), as the headline
   goal-conditional-trajectory number.
