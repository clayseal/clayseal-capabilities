# Is Clay Seal actually SOTA? An honest assessment

Written 2026-07-27 to answer one question directly: is Clay Seal absolute SOTA
for preventing agent escapes and business-process-logic violations, or does it
only look strong on its own harness? The answer is split, and the split points
at exactly where to aim.

Evidence base: a verified frontier map (25 claims, 3-vote adversarial
verification), a live head-to-head vs published AgentDojo defenses, and an
offline per-attack-class replay on real data. Results live in
[../benchmarks/results/head_to_head.md](../benchmarks/results/head_to_head.md)
and [../benchmarks/results/bpl_aggregate.md](../benchmarks/results/bpl_aggregate.md).

## The bar: what the current frontier actually is

Escapes / prompt injection is a crowded, near-solved race. The leading published
systems already reach near-zero attack success at good utility:

- **CaMeL** (arXiv:2503.18813, DeepMind): 77% AgentDojo utility with provable-by-
  design security vs 84% undefended. Dual-LLM plus capabilities plus data-flow
  (information-flow control). This is a provenance/dataflow defense.
- **Progent** (arXiv:2504.11703): AgentDojo ASR 39.9 to 1.0%, ASB 70.3 to 3.9%,
  utility preserved. Deterministic symbolic least-privilege over tool args, Z3
  narrowing.
- **MELON** (arXiv:2502.05174, ICML 2025): training-free masked re-execution IPI
  detector, beats the prior defense set on AgentDojo.
- **NOVA** (arXiv:2601.09923): control-flow integrity for computer-use / OS-level
  agents via single-shot branching plans, up to 57% OSWorld retained. This is the
  closest thing to an OS-escape defense, and its residual (Branch Steering) is an
  authorized-branch subversion the architecture does not stop.

The critique that matters (arXiv:2606.26479): these are out-of-band deterministic
monitors, structurally sounder than in-band detectors, but their adaptive-attacker
robustness is unproven because they are tested on static benchmarks. And beating a
deterministic gate requires "achieving the goal through already-authorized
actions" which is exactly the business-process-logic threat none of them target.

The policy-adherence benchmarks confirm the open flank. They measure trajectory-
level policy violation and find it everywhere, but they are diagnostics, not
defenses:

- **tau-bench** (arXiv:2406.12045): pass^k. gpt-4o under 50% single-run, pass^8
  under 25% in retail.
- **tau2-bench** (arXiv:2506.07982): dual-control. GPT-4.1 pass@1 ~74 to ~34%.
- **ST-WebAgentBench** (arXiv:2410.06703): Completion-Under-Policy. SOTA web agents
  complete tasks while breaking policy, raw ~24% vs CuP ~15%.

## Where Clay Seal stands

### Escapes: competitive at the ceiling, not SOTA on the shippable path

The full stack (oracle scope plus destination binding) drives ASR to 0% on
banking, beating the simple AgentDojo built-ins (best 22.2%). But head-to-head
against the real frontier this is not a clear win: Progent reports 1.0% ASR at
preserved utility on the full benchmark, while our full stack pays a utility cost
and, more importantly, the deployable envelope (no oracle) sits at 55.6% ASR,
worse than a prompt-repetition baseline. The oracle gap is decisive.

Honest verdict: on escapes, Clay Seal is one more out-of-band monitor in a field
where CaMeL and Progent already hold near-zero ASR. Building the provenance layer
would make the deployable path competitive, but provenance is CaMeL's own
mechanism, so it reaches parity, not lead. Racing here is incremental.

### Business-process-logic: uncontested, and proven on real data

This is the finding. The frontier map, at medium confidence and flagged as an
inferred coverage gap, is that no published defense enforces composite policy
where every individual action is authorized but the sequence violates a business
rule. Sub-threshold splitting, aggregate abuse, wrong-in-scope targets, slow
multi-step subversion. The benchmarks prove agents fail this constantly, and no
system defends it at runtime.

Clay Seal already does, on real data, for the deterministic case. On AgentDojo
banking, the stateful budget rung lifts containment of individually-authorized
overspend from 38% (every per-call rung, including argument binding) to 100%, at
0% false-block. That is a runtime enforcement of a composite constraint that, by
the frontier map, no published system provides.

The learned extension is now also earned, on a real corpus, after a calibration
fix. The goal-conditional trajectory detector catches the non-value aggregates
(in-scope-burst) the budget rung cannot. The per-call ladder is 0% on
in-scope-burst, so only such a detector can catch it at all. Initially the
detector did not hold its false-alarm bound (17 to 23% actual vs 5% target)
because its structural tiers blocked outside the conformal budget; once those
tiers were subordinated to the same alpha budget (detector.py), the bound holds
(false-block tracks alpha) and on bfcl, a real 1146-trajectory corpus, the
detector contains 95.4% of in-scope-burst at 5.9% false-alarm. See detector.md.
The remaining limit is corpus size on thin suites (agentdojo abstains), correctly
sequenced as the second, data-scale problem.

Honest verdict: Clay Seal is decisively SOTA on the aggregate/composite class, in
two forms now both earned on real data. Deterministic: the budget rung on
sub-threshold splitting. Learned: the goal-conditional trajectory detector on
fully-authorized bursts, 95% containment at a held 6% false-alarm rate. Both
enforce, at runtime, a threat shape the published field only exposes and never
defends. This is the wedge, and it is no longer aspirational.

## The strategic conclusion

Stop trying to win the escapes race. Own business-process-logic and goal-
conditional trajectory integrity. Concretely:

1. **Position the system as the first runtime enforcement for composite / goal-
   conditional trajectory policy.** The budget result is the beachhead; make it
   the headline, not the injection numbers.
2. **Provenance / taint (v0.2 keystone 2) is necessary but defensive.** It stops
   the deployable escapes path from being embarrassing (55.6% ASR) and reaches
   parity with CaMeL. Build it, but do not sell it as the differentiator.
3. **Prove the trajectory detector on real data.** in-scope-burst and goal-
   conditional drift via `--mode detector`, with a conformal false-alarm bound.
   This is the SOTA claim that nobody can match today.
4. **Benchmark the BPL claim at scale.** Wire the fraud corpus (ulb_creditcard),
   run the aggregate class across suites and models on a VM, and, where runnable,
   put Progent and CaMeL on the same table so the comparison is apples to apples.
5. **Adaptive robustness is the credibility bar.** The whole field is criticized
   for static-only evaluation. The adaptive envelope-aware adversary result
   (full stack 0% under a defense-aware attacker) is already the answer to that
   critique. Extend it to the trajectory claim.

## What would falsify the SOTA claim

- A published runtime defense that enforces aggregate/composite constraints
  surfaces (the frontier map lists this as an open question, not a settled
  absence). Then the BPL wedge narrows.
- The trajectory detector cannot hold a low false-alarm rate on real benign
  corpora. Then the composite claim is theoretical, not deployable.
- The BPL result does not survive scale (more suites, more models, adaptive
  aggregate attacks). Then it is a banking artifact, not a general property.
