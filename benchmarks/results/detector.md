# Trajectory detector: the uncontested class, not yet an earned claim

The goal-conditional trajectory detector is meant to catch the class even the
budget rung cannot: fully-authorized aggregates like in-scope-burst (an
authorized read repeated into a scanning/exfil burst), where every action passes
every per-call check and the sequence is the attack. This is the frontier the
research map found empty. Here is what it actually does today, stated straight.

## The setup is right: the per-call ladder is totally blind

On AgentDojo, in-scope-burst containment across the entire enforcement ladder:

| Engine | in-scope-burst containment |
|---|--:|
| tool-allowlist through task-scope+binding+budget | **0%** |
| deny-all | 100% (at 100% false-block) |

Every per-call rung, including the stateful budget rung, scores 0. Only a
trajectory-level detector can catch this class at all. That part of the thesis
holds by construction.

## The detector does not yet hold its bound

Fit the goal-conditional detector (ngram scorer, conformal alpha=0.05) on benign
trajectories, measure containment on in-scope-burst and false-block on held-out
benign:

| corpus | n_train benign | in-scope-burst containment | benign false-block |
|---|--:|--:|--:|
| agentdojo | 46 | 48.4% | 22.6% |
| atif (real long trajectories) | 22 | 0.0% (abstains) | 0.0% |
| agentdojo + atif | 68 | 32.6% | 17.4% |

Two problems, both real:

1. The false-alarm bound is violated. alpha was set to 0.05; actual benign
   false-block is 17 to 23 percent whenever the detector is active. The conformal
   guarantee is not holding on these corpora, so the block decisions are not
   trustworthy yet.
2. Containment is mediocre and non-monotone in data. 48 percent on agentdojo, 0
   on atif (too few benign per goal bucket, so the structural tiers abstain by
   design rather than over-flag), 33 percent combined. More data did not help
   because adding atif diluted the per-goal buckets.

## Diagnosis: confirmed, and it is NOT data starvation

The first hypothesis (too few benign trajectories) is wrong. Two checks kill it:

1. Data scaling does not help. false-block across corpora: agentdojo 46 train
   22.6%, tau2 60 train 15.0%, bfcl 687 train 27.5%, combined 793 train 24.7%.
   From 46 to 793 benign there is no downward trend. bfcl at 687 is the worst.
2. false-block does not respond to alpha at the low end. tau2 is 15.0% at BOTH
   alpha=0.01 and alpha=0.05; bfcl is 27.5% at both. Lowering the conformal
   budget changes nothing, so those false-blocks are not coming from the
   conformal scorer.

Root cause, confirmed in code (detector.py `AssessResult.blocked`):

    blocked = self.structural_block or any(v.decision is BLOCK for v in verdicts)

The structural tiers (Waymo path-envelope in reachability.py, AML analytics in
aml.py) set `structural_block` and are OR'd into the decision OUTSIDE the
conformal budget. The docstring claims they are "strong low-false-positive
structural signals" that "can block outright", but on real heterogeneous corpora
they fire on 15 to 27 percent of benign trajectories. Only the learned scorer is
bounded by alpha; the structural tiers are not, so the total false-alarm rate is
not bounded by anything. The headline property of this layer, a conformally
bounded false-alarm rate, does not hold as implemented.

## The fix (concrete, and it is calibration, not data)

Subordinate the structural tiers to the same conformal budget. Calibrate each
structural corridor threshold on the held-out benign slice so at most alpha of
benign falls outside it, and combine the tiers at the trajectory level so the
union false-alarm rate stays near alpha (not a per-tier OR that inflates it).
Alternatively, demote structural-tier hits to step-up rather than hard block, so
they raise friction but do not count as blocks. Either way this is a bounded
calibration change in detector.py / reachability.py / aml.py, testable by
re-running this sweep and confirming benign false-block tracks alpha.

Only after the bound holds does corpus scale (ATIF-scale, then iVisor at-scale
trajectory capture, docs/ivisor_integration.md) become the lever for containment.
Data was going to be the second problem; it is not the first one.

## After the fix: the bound holds, and the claim is earned on real data

The fix landed in detector.py: the structural tiers now fit on the same slice as
the scorer, the path-envelope penalty is conformally calibrated on the held-out
benign slice, and AML blocks only when its held-out benign flag rate is under
alpha. Re-running the exact sweep at alpha=0.05:

| corpus | before (containment / false-block) | after (containment / false-block) |
|---|--:|--:|
| tau2 | 75% / 15.0% | 75% / **5.0%** |
| bfcl | 99% / 27.5% | 95.4% / **5.9%** |
| agentdojo | 48% / 22.6% | 0% / 0% (too small, abstains) |

And false-block now responds to alpha as a conformal bound must: tau2 5.0% at
alpha 0.05 rising to 22.5% at 0.20; bfcl 0.0% at 0.01, 5.9% at 0.05, 27.7% at
0.20. The guarantee is real, not nominal.

The headline: on bfcl, a real function-calling corpus of 1146 trajectories, the
goal-conditional detector contains **95.4 percent of in-scope-burst at a 5.9
percent false-alarm rate**, on the fully-authorized aggregate class the entire
per-call ladder scores 0 percent on. That is a runtime defense for a threat shape
the published field only exposes and never defends, now earned empirically with a
false-alarm bound that holds.

The agentdojo 0 percent is the honest small-corpus floor: 46 short benign
trajectories are too few to calibrate a corridor, so the detector abstains rather
than over-flag (0 containment at 0 false-block). This is exactly where corpus
scale (ATIF, then iVisor capture) is the lever, now that calibration is fixed.

## The full goal-conditional trajectory SOTA table

Not one class on one corpus. The detector at alpha=0.05 across the aggregate /
composite attack classes on the large real corpora:

| corpus | in-scope-burst | goal-drift | connector-substitution | benign false-block |
|---|--:|--:|--:|--:|
| bfcl (1927 tasks) | 95.4% | 100% | 100% | 4.1 to 5.9% |
| tau2 (2545 tasks) | 75.0% | 100% | 100% | 5.0 to 8.4% |
| agentdojo (77 tasks) | 0% (abstains) | 100% | 100% | 0% |

The per-call enforcement ladder scores 0 percent on in-scope-burst at every rung,
because every action is authorized. The detector holds 95 percent (bfcl) and 75
percent (tau2) on that class at a false-alarm rate that stays near alpha across
all classes and corpora. goal-drift and connector-substitution are contained at
100 percent. This is a runtime defense of the composite / aggregate / goal-
conditional class across three corpora, at a bounded false-alarm rate, for a
threat shape the published field only exposes and never defends.

## Adaptive robustness: the honest frontier (corpus-dependent)

The field's central critique is static-only evaluation. So: a defense-aware
aggregate attacker that knows the detector mechanism and shapes the aggregate to
stay in-corridor. Three strategies, at alpha=0.05:

- naive: repeat one authorized read many times (hits path-envelope max_count).
- fanout: spread the reads across every distinct authorized tool (evades the
  per-token count).
- stealth: a few reads at near-benign volume, reusing only seen tools.

| corpus | naive | fanout | stealth |
|---|--:|--:|--:|
| bfcl (homogeneous) | 95.4% | 95.4% | 87.6% |
| tau2 (heterogeneous) | 75.0% | 27.5% | 5.0% |

The result is split and must not be overstated. On bfcl the benign corridor is
tight (rich, homogeneous per-goal data), so the attacker cannot evade: fan-out
does not help and even a minimal 3-read stealth aggregate is caught 87.6%. On
tau2 the corridor is loose (heterogeneous dual-control benign), so a defense-aware
attacker evades: fan-out drops containment to 27.5% and stealth collapses to the
5% false-alarm floor, i.e. a small aggregate is statistically indistinguishable
from benign by trajectory shape alone. The naive tau2 75% is not an
adaptive-robust number.

The interpretation is precise and it is the same tradeoff as the escapes adaptive
adversary: the attacker cannot both stay in the benign corridor and move a large
aggregate. Where benign is homogeneous the corridor squeezes that to near-zero
residual; where benign is heterogeneous, small aggregates fit inside natural
variation and shape alone cannot catch them. That residual is not a shape problem
to be tuned away, it is a job for a different signal: provenance / taint catches a
read driven by untrusted context regardless of volume, which is exactly the
stealth case shape misses. Shape and taint are complementary, and the honest claim
is shape-robust on homogeneous workloads, taint-dependent on heterogeneous ones.

## Honest standing of the SOTA claim

- The deterministic aggregate enforcement (the budget rung, sub-threshold
  splitting) is PROVEN on real data. See bpl_aggregate.md.
- The learned goal-conditional trajectory detector now holds its false-alarm
  bound and contains 95 percent of in-scope-burst at ~6 percent false-alarm on
  bfcl, a class the per-call ladder cannot touch, and this survives a defense-
  aware adaptive attacker (fan-out 95 percent, stealth 88 percent). On a
  homogeneous corpus it is a genuine, adaptive-robust SOTA result.
- The honest boundary: on a heterogeneous corpus (tau2) the naive 75 percent does
  NOT survive the adaptive attacker (fan-out 27 percent, stealth 5 percent). Shape
  alone cannot catch a small aggregate that fits inside heterogeneous benign
  variation. That residual is the province of provenance / taint (origin, not
  volume), which is complementary to shape, not a tuning of it.
- The remaining data limit is corpus size on small suites (agentdojo abstains),
  correctly sequenced after calibration.

## Next

1. Scale the benign corpus on the thin suites (ATIF-scale, ultimately iVisor
   syscall/tool trajectory capture) so agentdojo-like buckets stop abstaining.
2. Train the transformer scorer on it and confirm the bound still holds and
   containment rises on the harder buckets.
3. Report containment on the full class set (in-scope-burst, goal-drift,
   structuring, slow-drift) across suites, with the adaptive aggregate attack, as
   the headline goal-conditional-trajectory SOTA number.
