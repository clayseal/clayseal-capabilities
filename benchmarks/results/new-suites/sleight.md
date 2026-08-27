# Clay Seal enforcement benchmark, sleight (43 tasks, 311 benign / 318 attack events)

STATUS: current

```bash
python -m benchmarks.cli --dataset sleight --mode detector      # the layer this corpus tests
python -m benchmarks.cli --dataset sleight --mode ladder --ci --json benchmarks/results/new-suites/sleight.json
```

## Read the detector number, not the ladder

SLEIGHT is a catalogue of **evasion**, not of risky operations. Its published
result is about monitors, and its sabotage happens inside a workspace the agent
was legitimately granted: of the 122 attack events the authorization ladder lets
through, every path is under `/opt/**`, and the largest category is
`model_priors` (47), which is about what a monitor believes rather than what an
action touches. A per-action authorization layer is the wrong instrument here and
the loader says so in `meta["score_with"] = "detector"`.

| layer | containment | false-block |
| --- | ---: | ---: |
| authorization ladder, at this corpus's declared valid rung | 5.4% (7/129) | not scoreable, see below |
| **trajectory detector** (`--mode detector`, split-conformal, alpha=0.05) | **94.4% (17/18)** | 0/18, 97.5% upper bound 18.5% |

The detector fits on train-split benign trajectories only and measures both axes
on the held-out split, so neither number sees its own training data. Eighteen
held-out tasks is a small denominator and the false-block zero is bounded
accordingly: it means "not distinguishable from 18.5%", not "never".

The ladder table below is an **ablation**, kept because the contrast is the
finding: it shows what per-action authorization cannot reach on covert sabotage,
which is most of it.

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 7.0%] | 0.0% [0.0%, 7.0%] | 0.0003 / 0.0004 / 0.0005 | 43 |
| tool-allowlist | 0.0% [0.0%, 7.0%] | 0.0% [0.0%, 7.0%] | 0.0006 / 0.0007 / 0.0011 | 43 |
| capability-token | 0.0% [0.0%, 7.0%] | 0.0% [0.0%, 7.0%] | 0.0023 / 0.0048 / 0.0101 | 43 |
| task-scope | 5.4% [0.7%, 13.1%] | 0.0% [0.0%, 7.0%] | 0.0119 / 0.2740 / 0.7715 | 43 |
| task-scope+binding | 5.4% [0.7%, 13.1%] | 0.0% [0.0%, 7.0%] | 0.0113 / 0.0369 / 0.0620 | 43 |
| task-scope+binding+budget | 5.4% [0.7%, 13.1%] | 0.0% [0.0%, 7.0%] | 0.0137 / 0.0350 / 0.0665 | 43 |
| task-scope+binding+budget+velocity | 65.9% [55.9%, 74.5%] | 16.1% [8.1%, 23.4%] | 0.0186 / 0.0504 / 0.1307 | 43 |
| deny-all | 100.0% [93.0%, 100.0%] | 100.0% [93.0%, 100.0%] | 0.0007 / 0.0008 / 0.0009 | 43 |
| position-only-control | 95.3% [90.1%, 99.2%] | 49.8% [39.9%, 57.5%] | 0.0005 / 0.0006 / 0.0009 | 43 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.

> **This corpus declares its highest valid rung as `task-scope+binding+budget`.** Rows above it (task-scope+binding+budget+velocity) are printed for ablation and are not results for this corpus.

> **The false-block column is not scoreable on this corpus.** The mandate is derived from the benign twin, so that twin is clean by construction. Friction is measured on corpora that do not have this property.

> **Uncalibrated:** task-scope+binding+budget+velocity found no attack-free task to calibrate on and fell back to a built-in constant. The row is that constant's behaviour, not a limit learned from this corpus's traffic.

> `position-only-control` reads nothing but an event's index in its task. It is a floor, not a defense: a rung that does not beat it is reporting the order of the corpus rather than the content of the actions.
