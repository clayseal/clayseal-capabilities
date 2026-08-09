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
| Target-shaped containment (RedCode / IPI / path egress) ≈100% | ready | `results/new-suites/redcode.md`, scoreboard | Do not pool with ASB/InjecAgent |
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
| Replay false-block 0% | blocked as operational FP | scoreboard legend | Replay FB ≠ production FP; use live ladder |
| ULB AUC / IBM AML fan-out | ready (analytics) | `results/aml_validation.md` | Analytics layer, not per-call authz |

## Forbidden claims (auto-fail review)

1. Pooled containment that includes `asb` or `injecagent` (`SATURATED` in `scoreboard.py`).
2. Quoting AgentHarm / SLEIGHT / AdvBench-agent containment as a product win.
3. Quoting replay false-block as operational false-positive rate.
4. Omitting AgentDyn 0% utility when discussing open-ended tasks.
5. Claiming Tier-4 live iVisor numbers from sample-trace replay alone.
6. Mixing L3 receipts plumbing pass rates with L2 ASR claims.

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
