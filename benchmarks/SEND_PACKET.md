# Clay Seal Capabilities — security-buyer send packet

Status enum: `ready` · `partial` · `blocked`. A claim is only citable when its
status is `ready` and its caveat is attached. This is the MITRE-style honesty
contract from `docs/benchmark_program.md`.

## Reproduce (deterministic)

```bash
git -C /path/to/agentauth-capabilities rev-parse HEAD   # record SHA
benchmarks/fetch_corpora.sh
python -m benchmarks.verify_corpus
benchmarks/run_all.sh                 # or --quick for smoke
# artifacts: benchmarks/results/scoreboard.json + *.md + syscall_tier.md
```

Live keystones (API $, separate):

```bash
# AgentDojo H2H / model ladder / BPL — see benchmarks/live/ and
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
| Sequence / BPL ≈0% violation vs Progent/CaMeL ≈100% | ready | `results/bpl_head_to_head.md` | Sample size modest (n≈20) |
| Live AgentDojo ASR ≈0% (gpt-4o-mini, important_instructions) | ready | `results/head_to_head_injection.md`, `pooled_asr.md` | Utility cost is the tradeoff; report it |
| Detector closes aggregate bursts (BFCL / τ²) | ready | `results/detector.md` | Per-call ladder scores 0% on this class |
| Content-defined harm (AgentHarm / SLEIGHT / AdvBench-agent) | ready (ceiling) | `results/agentharm_ceiling.md`, `why_we_fail.md` | **Not** an authorization win; do not optimize via hard-deny of untargeted tools |
| ASB / InjecAgent 100% containment | ready (saturated) | scoreboard `SATURATED` | **Never** in a pooled headline |
| ToolEmu normalized traces | partial → ready when fixture/corpus present | `fixtures/toolemu/`, scoreboard | Raw toolkit mapping has **no** attack events |
| MCP-attack (poisoned tool / deputy / arg mutation) | ready (fixture) | `fixtures/mcp_attack/`, `new-suites/mcp_attack.md` | Fixture, not a public leaderboard |
| Syscall tier (iVisor) | partial | `results/syscall_tier.md` | Trace replay ≠ live sandbox; 05/06 may be non-events on fd-3 |
| AgentDyn open-ended utility | ready (failure) | `results/agentdyn.md` | Must appear in any honest packet; typed-plan/`reclear` is the fix path |
| Replay false-block 0% | blocked as operational FP | scoreboard legend | Replay FB ≠ production FP; use live ladder. Suppress the `FB=0.00%` cell entirely where `heldout.py` cannot produce a split, rather than printing a circular zero beside a real containment number. |
| Adaptive adversary vs the SHIPPED gateway | ready | `results/adaptive_stack.md` | Four objectives flat at 100% across blind/feedback/oracle. In-scope content staging is 100% at oracle **entirely via STEP_UP** — the pessimistic supervised row collapses to the floor, so quote both rows or neither. |
| In-scope staging, path-mention objective | **known gap** | `results/in_scope_exfiltration.md`, `results/adaptive_stack.md` | The shipped stack scores exactly its floor rung, +0.0 lift at oracle. Unchanged. |
| ULB AUC / IBM AML fan-out | ready (analytics) | `results/aml_validation.md` | Analytics layer, not per-call authz |

## Configuration the published numbers were measured under

A containment number is a property of a configuration, not of a name. Two
switches change it materially and both are now explicit rather than implied.

| switch | measured setting | what it means |
| --- | --- | --- |
| `session_rules` | **on** | Five corpus-derived pattern rules (`agentauth/capabilities/session_rules.py`) matching shell command text — `ln -s` then `zip`, `awk $N` vs an observed CSV header, absolute-line `sed` after an expanding edit — one of which carries a corpus's own project name as a literal. They were inlined in the broker and unswitchable; they are now named and default OFF on the raw `SessionBroker` and ON in `DeployableStack.from_goal`, which is the profile every published number came from. STEP_UP only, never DENY. **Any containment claim for a workload unlike these corpora should be re-measured with `session_rules=False`.** |
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
11. Any containment number quoted without stating that `session_rules` was on.
    The pack is corpus-derived; quoting a number it contributed to as a general
    property of the system is the overfitting this packet exists to surface.
12. Quoting the in-scope content-staging containment without the `step-up=allow`
    row beside it. All of that containment is supervision; under a human who
    approves everything it is the floor's number.
13. Citing an adaptive result against a LADDER RUNG as an adaptive result for the
    product. The ladder is an ablation. `results/adaptive_stack.md` is the only
    adaptive run against `DeployableStack`.

## Packet contents (zip / folder)

- `SEND_PACKET.md` (this file)
- `results/scoreboard.json` + `scoreboard.md`
- `results/head_to_head_injection.md`, `bpl_head_to_head.md`, `live_ladder.md`
- `results/four_axes.md`, `why_we_fail.md`, `agentdyn.md`
- `results/syscall_tier.md`
- `docs/CYBERTOOL_MEMO_REVISED.tex` or `clayseal_benchmarks.tex` with Reproduce block
- git SHA + `corpus_manifest.json` hashes

Optional companion (evidence plane, not ASR):  
`agentauth-receipts/benchmarks/demo/auditor_packet_10.zip`.

## Architecture shipped with this packet

Containing-object provenance (structured → allow; free-text of goal-named object → `STEP_UP`), typed plan slots + `reclear_extend_template`, friction-budget rate + `utility_report()` triple (autonomous / supervised / endorsements-per-action). See `docs/production_sota_path.md` and `python/tests/test_containing_object_provenance.py`.
