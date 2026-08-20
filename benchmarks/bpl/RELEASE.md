# BPL release notes

## v1.1 (unreleased) — fairness and provenance

Core-12 and Hard-24 membership is **unchanged**, so v1.0 numbers remain
comparable. What changed is how the comparison is set up.

**Every condition receives the policy.** `benchmarks/bpl/policy.py` adds a
declarative rule language and `policies.py` declares the rule for each Core
scenario. Previously the threshold reached the enforcer and the violation oracle
through the same Python name in 36 of 133 scenarios, and only the reference
defense was given it — so the table partly measured which condition had been told
the rule. The surviving claim is the architectural one: given the same policy, a
defense with no cross-call state cannot enforce an aggregate constraint.

**The comparison conditions are renamed for their class.** `progent` →
`per-call`, `camel` → `dataflow-taint`. They were never those systems. `drift`
and `authgraph` keep their names as "-shaped" mechanism reproductions with
citations.

**Three new invariants**, each added after a negative control showed the previous
version did not catch a real corruption:

| check | catches |
| --- | --- |
| policy vs oracle on both scripts | a mis-transcribed threshold |
| grouped ceilings discriminate | a per-vendor rule silently acting global |
| rule fields exist on the tool schema | a rule summing a field the tool lacks |

**A datasheet.** [`DATASHEET.md`](DATASHEET.md), Gebru et al. format, with
limitations and ethics stated rather than footnoted.

**Coverage is reported, not implied.** `--policy-coverage` prints 12 of 133
declarative, so "not yet migrated" cannot read as "has no rule".

### Open before submission

- [ ] Re-run the Core-12 live H2H under the shared policy (tables currently
      carry a provenance caveat).
- [ ] Declarative policy for Hard-24.
- [ ] A second model on the live leaderboard.
- [ ] Scenarios contributed by someone who did not write the reference defense —
      the limitation that bounds every result here.

---

## v1.0 release notes

Standalone release: https://github.com/clayseal/bpl-benchmark

Frozen suites live in [`SUITES.yaml`](SUITES.yaml). Do not expand Core/Hard
without a version bump.

## Suites

| Suite | Size | Use |
|-------|------|-----|
| **core** | 12 | Default paper / leaderboard |
| **hard** | 24 | Harder defense eval; report separately |
| **research_quarantine** | 12 | Paradox / near-algorithmic; not a ClaySeal score |
| **full** | ~132 | Growing pack; appendix only |

## Scorecard

Per scenario × condition (`none` / `progent` / `camel` / `drift` / `authgraph` /
`clayseal`):

- **V:** violation rate (lower better)
- **P:** mean task progress (higher better)
- **U = P × (1 − V):** utility-aware suite macro

Progress convention:

- **Gold-5 legacy:** fraction of requested work (unchanged vs published H2H)
- **Other Core:** fraction of policy-allowed work (budget fill / legal completion)

## Commands

```bash
python -m benchmarks.live.bpl_live --list --suite core
pytest benchmarks/tests/test_bpl_scenarios.py -q
./scripts/paper/run_bpl_core_h2h.sh
# or: RUNS=20 MODEL=gpt-4o-mini-2024-07-18 ./scripts/paper/run_bpl_core_h2h.sh
```

## Non-goals

See `non_goals` in `SUITES.yaml`. Not jailbreak ASR, CVE/malware, dual-use
bio/chem/nuclear, single out-of-schema denies, or ClaySeal SOTA claims on
`clayseal_expected: open`.

## Pre-release checklist

1. [x] Freeze Core-12 + Hard-24 in `SUITES.yaml`
2. [x] Normalize progress on non-legacy Core aggregates
3. [x] Live Core H2H (≥8 runs × 4 conditions). Done for one model (gpt-5-mini via
   Azure). Second model optional.
4. [x] Results page (gold + Core; Full appendix)
5. [x] How-to evaluate / add scenario docs
6. [x] Explicit non-goals
7. [x] Quarantine paradox from Core/Hard
