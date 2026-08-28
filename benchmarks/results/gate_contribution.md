# What each gate contributes, measured by removing it

STATUS: current

```bash
python -m benchmarks.gate_contribution
```

Reading the code cannot tell you which gates are load-bearing, because every
gate looks load-bearing in isolation. This removes one at a time and re-runs
every scored population.

**Unique catch** is attacks contained by the full stack that escape when only
this gate is removed. It is deliberately not "attacks this gate denied": a gate
that denies what three other gates also deny contributes nothing, and the denial
reason still credits it. **First to refuse** is held-out benign events where
this gate produced the denial.

## Result

9 attack corpora, 3,094 contained attack events, held-out tau2 for the benign
side.

| gate | unique catch | first to refuse (benign) | |
| --- | ---: | ---: | --- |
| resource scope | **303** | 0 | load-bearing |
| intent envelope | **71** | 0 | load-bearing |
| flow tracker | **4** | 0 | load-bearing |
| **tool allow-list** | **0** | **1,342 (100%)** | **pure friction here** |
| capability list | 0 | 0 | redundant here |
| credential payloads | 0 | 0 | redundant here |
| egress | not exercised | 0 | no verdict |
| value budget | not exercised | 0 | no verdict |
| call budget | not exercised | 0 | no verdict |
| detector | not exercised | 0 | no verdict |
| provenance | not exercised | 0 | no verdict |
| conditional tools | not exercised | 0 | no verdict |

**Three gates catch everything.** Resource scope, the intent envelope and the
flow tracker account for all 378 unique catches. Every other exercised gate is
redundant on these corpora.

**One gate is the entire benign cost.** The tool allow-list produces 100% of the
held-out benign refusals and zero unique catches. That is the finding
[observed_grant.md](observed_grant.md) acts on, arrived at here independently
and from the other direction.

## The distinction that keeps this tool safe

"Not exercised" and "zero unique catch" are different statements and the report
separates them. A gate that fired and was merely redundant is a finding. A gate
that never fired was not tested, and reading its zero as "contributes nothing"
is how someone deletes the budget rungs, **which carry the 83.3% headline in the
README** and are measured by `bpl_sweep`, a suite this scan does not load. Six
of the twelve gates are in that category and none of them is evidence for
anything here.

## Limits

- **Nine corpora, one benign source.** Held-out tau2 is the only observed-derived
  benign corpus large enough to hold out, so the benign column rests on it alone.
- **Single ablation.** Removing one gate at a time cannot see a set that is
  jointly load-bearing and individually redundant. The tool allow-list, the
  capability list and the resource scope are exactly that shape for benign
  traffic, which is why the *unique cost* column reads 0 of 5,441 for all three while
  the first-refuser column reads 1,342 of 1,342. Removing any one changes nothing;
  removing the set changes everything. That pair is the whole observed-grant
  result and a single-ablation scan cannot produce it on its own.
- **Redundancy is corpus-relative.** A gate contributing nothing on nine corpora
  may be the only thing standing between an attacker and a tenth.
