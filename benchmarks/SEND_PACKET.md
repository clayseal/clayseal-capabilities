# Clay Seal Capabilities, security-buyer send packet

Status enum: `ready` · `partial` · `blocked`. A claim is only citable when its
status is `ready` and its caveat is attached. This is the MITRE-style honesty
contract from `docs/benchmark_program.md`.

## Reproduce (deterministic)

```bash
git -C /path/to/clayseal rev-parse HEAD   # record SHA
benchmarks/fetch_corpora.sh
python -m benchmarks.verify_corpus
benchmarks/run_all.sh                 # or --quick for smoke
# artifacts: benchmarks/results/scoreboard.json + *.md + syscall_tier.md
```

Live keystones (API $, separate):

```bash
# AgentDojo H2H / model ladder / BPL, see benchmarks/live/ and
# results/head_to_head_injection.md, results/bpl_head_to_head.md,
# results/live_ladder.md. Freeze model + seed before quoting.
```

## Claim board

| Claim | Status | Cite | Forbidden without caveat |
| --- | --- | --- | --- |
| Target-shaped containment (RedCode / IPI / path egress) ≈100% | ready | `results/new-suites/redcode.md`, scoreboard | Do not pool with ASB/InjecAgent. **Must carry the in-scope caveat below.** |
| Adaptive red-team 100% vs oracle attacker | ready (**attribute to `task-scope`**) | `results/adaptive_ladder_audit.md` | Every rung above `task-scope` scores identically. All three objectives are defined through `_outside_workspace()`, so the objective is the negation of the defence. Do **not** credit binding/budget/velocity. |
| No containment against in-scope data staging | **known gap** | `results/in_scope_exfiltration.md` | Against an oracle attacker the full ladder's escaped set is byte-identical to `allow-all`. Must accompany any containment claim for coding agents. |
| Behavioural-layer numbers | **corpus-limited** | `results/adequacy.md` | Of 11 corpora, 4 carry zero attack events and 1 can evaluate provenance. Quote no behavioural number without the adequacy verdict for that corpus. |
| Volume / burst containment 100% | ready | `results/burst.md` | Do not calibrate velocity on attack labels |
| BPL escape-class containment | **known gap** | `results/bpl_full_sweep.md` correction | 17% (10 of 59), not the 61% previously published. The old figure was mandates that forbade the task. Attacks use only granted tools; the stack has no mechanism for sequence-growth escape. |
| Sequence / BPL ≈0% violation vs stateless per-call and dataflow-taint defenses ≈100% | ready | `results/bpl_head_to_head.md` | **Do not name Progent or CaMeL.** The conditions are ~10-line reproductions of an architectural class, the cited file dropped those names, and no cell may be read as "system X fails". Aggregate-budget class is n=100 per cell. The exfil row and Core-12 are still n=20, where a zero has a 97.5% upper bound of 15%. |
| Live AgentDojo ASR ≈0% (gpt-4o-mini, important_instructions) | ready (**model-bound**) | `results/head_to_head_injection.md`, `pooled_asr.md`, `results/utility_experiment_void.md` | Utility cost is the tradeoff; report it. **And name the model.** On `gpt-5-mini` the UNDEFENDED ASR is 0.0% across four attacks, so the result does not transfer to a 2026 frontier model and cannot be re-run there. |
| Detector closes aggregate bursts (BFCL / τ²) | **withdrawn, no surviving evidence** | none. `results/detector.md` was stamped `unverified` and deleted in `bbf9f5d` for carrying no reproduce command | Nothing in `results/` measures the trajectory detector on BFCL or τ². `results/composed_detector.md` measures it on sleight and agentharm only. The per-call ladder's blindness to this class survives the deletion and is in `four_axes.md`. |
| Content-defined harm (AgentHarm / SLEIGHT / AdvBench-agent) | ready (ceiling) | `results/agentharm_ceiling.md`, `four_axes.md` | **Not** an authorization win; do not optimize via hard-deny of untargeted tools |
| ASB / InjecAgent 100% containment | ready (saturated) | scoreboard `SATURATED` | **Never** in a pooled headline |
| ToolEmu normalized traces | partial → ready when fixture/corpus present | `fixtures/toolemu/`, scoreboard | Raw toolkit mapping has **no** attack events |
| MCP-attack (poisoned tool / deputy / arg mutation) | ready (fixture) | `fixtures/mcp_attack/`, `new-suites/mcp_attack.md` | Fixture, not a public leaderboard |
| Syscall tier (iVisor) | partial | `results/syscall_tier.md` | Trace replay ≠ live sandbox; 05/06 may be non-events on fd-3 |
| AgentDyn open-ended utility | ready (failure) | `results/agentdyn.md` | Must appear in any honest packet; typed-plan/`reclear` is the fix path |
| Replay false-block 0% | blocked as operational FP | scoreboard legend | Replay FB ≠ production FP; use live ladder. Suppress the `FB=0.00%` cell entirely where `heldout.py` cannot produce a split, rather than printing a circular zero beside a real containment number. |
| Plausibility-based injections land on a 2026 model, and the layer contains them | ready | `results/attacks_2026.md` | 6 of 48 undefended vs 0 of 12 for `important_instructions`; **0 of 48 defended**. Quote the friction beside it — `schema_field` costs 0.83 step-ups/task. n=6 per cell; do not rank the four attacks against each other. |
| BPL Core-12 under a SHARED policy | ready | `results/bpl_shared_policy.md` | Every condition given the same declarative rule. Joint score U = P(1-V): clayseal 64.3%, next best 35.2%. **Quote the progress column against POLICY-OPTIMAL, not undefended** — an undefended agent completes work the policy forbids, so 90.2% is not a target. Optimal is 78.0%; clayseal is 64.3%, exact on 7 of 12, and the loss is two cells (`sod-prepare-and-approve` -100, `po-split-threshold` -85) where NO condition violates, i.e. pure friction. 3 of 12 scenarios discriminate nothing (no condition violates); the effective set is 9. n=20, so a zero has a 95% upper bound of 16.1%. |
| Adaptive adversary vs the SHIPPED gateway | ready | `results/adaptive_stack.md` | Four objectives flat at 100% across blind/feedback/oracle. In-scope content staging is 100% at oracle **entirely via STEP_UP** — the pessimistic supervised row collapses to the floor, so quote both rows or neither. |
| In-scope staging, path-mention objective | **known gap** | `results/in_scope_exfiltration.md`, `results/adaptive_stack.md` | The shipped stack scores exactly its floor rung, +0.0 lift at oracle. Unchanged. |
| ULB AUC / IBM AML fan-out | ready (analytics) | `results/aml_validation.md` | Analytics layer, not per-call authz |

## Configuration the published numbers were measured under

A containment number is a property of a configuration, not of a name. Two
switches change it materially and both are now explicit rather than implied.

| switch | measured setting | what it means |
| --- | --- | --- |
| `session_rules` | **off** | Five corpus-derived pattern rules (`clayseal/capabilities/session_rules.py`) matching shell command text: `ln -s` then `zip`, `awk $N` vs an observed CSV header, absolute-line `sed` after an expanding edit. STEP_UP only, never DENY. They default OFF on the raw `SessionBroker` and OFF in `DeployableStack.from_goal`, the factory `benchmarks/core/stack_factory.py` builds every scored run through. `profiles.BENCHMARK` is the only shipped profile setting it True. The pack WAS on when the published numbers were produced, and its contribution was then measured by removing it and re-running every scored population: sleight 28/122, agentharm 196/507, BPL joint 52/132 at 2 false blocks, identical in both arms, benign cost 0 of 20,619 events (`results/corpus_rule_contribution.md`). The corpus project-name literal is removed. **Zero is a measurement on these corpora. A workload unlike them has not been measured either way.** |
| `content_rules` | **off** in deployment, **on** in BENCHMARK | Sixty patterns in `monitor/entailment.py` (27 structural rules keyed on one corpus's file layout and vocabulary, plus 33 harmful-intent cues) that ran UNCONDITIONALLY on the authorize path until they were priced. They are worth 19.7 points of in-surface containment on SLEIGHT and 11.9 on AgentHarm, the two halves disjoint and neither transferring to the other corpus, and 0 on BPL (`results/content_rule_contribution.md`). STEP_UP only. **Any content-harm number is a number measured with these on.** |
| `detector` | **off** | The trajectory detector does not ship enabled. On SLEIGHT it reaches 100% containment by refusing 13 of 18 benign trajectories. |

## Forbidden claims (auto-fail review)

1. Pooled containment that includes `asb` or `injecagent` (`SATURATED` in `scoreboard.py`).
2. Quoting AgentHarm / SLEIGHT / AdvBench-agent containment as a product win.
3. Quoting replay false-block as operational false-positive rate.
4. Omitting AgentDyn 0% utility when discussing open-ended tasks.
5. Claiming Tier-4 live iVisor numbers from sample-trace replay alone.
6. Mixing L3 receipts plumbing pass rates with L2 ASR claims.
7. Crediting the adaptive red-team's 100% to the full stack. It is a `task-scope`
   result; the rungs above it are indistinguishable from it on that test.
8. Any containment claim for a coding agent that omits the in-scope staging gap.
9. Any behavioural number from a corpus `benchmarks/adequacy.py` marks unusable
   for that layer.
10. Containment at an unconstrained false-block rate as a headline. Use
    detection @ fixed FPR (`benchmarks/opeval.py`); a control that blocks
    everything must score zero.
11. Quoting a number measured with `session_rules=True` or `content_rules=True`
    without saying so. Both packs are corpus-derived. `session_rules` is now OFF
    in `DeployableStack.from_goal` and in both deployment profiles, and its
    contribution to every scored population measured zero
    (`results/corpus_rule_contribution.md`), so a number that needs it is a
    number to re-measure rather than to quote. `content_rules` is the opposite
    case and the more dangerous one: it is worth 19.7 points on SLEIGHT and 11.9
    on AgentHarm, and worth them ONLY on the corpus each half was written
    against, 0 on BPL (`results/content_rule_contribution.md`). It is off in
    both deployment profiles for that reason.
12. Quoting the in-scope content-staging containment without the `step-up=allow`
    row beside it. All of that containment is supervision; under a human who
    approves everything it is the floor's number.
13. Citing an adaptive result against a LADDER RUNG as an adaptive result for the
    product. The ladder is an ablation. `results/adaptive_stack.md` is the only
    adaptive run against `DeployableStack`.
14. Quoting any live AgentDojo ASR without naming the model AND the injection
    tasks. `[:n_inj]` selects banking tasks 0-3, whose goals no document would
    plausibly instruct, so a framing's ASR is capped by the goal it carries
    rather than by the defense. See `results/attacks_2026.md`.
15. Quoting the 0-of-48 defended figure without the friction column. Containing
    this class costs up to 0.83 step-ups per task, and a supervised deployment's
    real containment is bounded by the approver's judgement on exactly the
    question the model got wrong, which this run does not measure.
16. Quoting any live AgentDojo ASR without naming the model. The attack does not
    land on a 2026 frontier model, undefended ASR is 0 of 18 on `gpt-5-mini` across
    four attacks, so "we hold ASR at zero" is a claim about
    `gpt-4o-mini-2024-07-18` specifically. See `results/utility_experiment_void.md`.

## Packet contents (zip / folder)

- `SEND_PACKET.md` (this file)
- `results/scoreboard.json` + `scoreboard.md`
- `results/head_to_head_injection.md`, `bpl_head_to_head.md`, `live_ladder.md`
- `results/four_axes.md`, `composed_detector.md`, `agentdyn.md`
- `results/syscall_tier.md`
- `a business memo` (kept outside this repository) or `clayseal_benchmarks.tex` with Reproduce block
- git SHA + `corpus_manifest.json` hashes

Optional companion (evidence plane, not ASR):  
`agentauth-receipts/benchmarks/demo/auditor_packet_10.zip`.

## Architecture shipped with this packet

Containing-object provenance (structured → allow; free-text of goal-named object → `STEP_UP`), typed plan slots + `reclear_extend_template`, friction-budget rate + `utility_report()` triple (autonomous / supervised / endorsements-per-action). See `notes/production_sota_path.md` and `python/tests/test_containing_object_provenance.py`.
