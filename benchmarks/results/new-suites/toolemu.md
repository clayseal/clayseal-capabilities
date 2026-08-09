
Wrote JSON results to benchmarks/results/new-suites/toolemu.json
# Clay Seal enforcement benchmark — toolemu (5 tasks, 10 benign / 5 attack events)

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 60.0%] | 0.0% [0.0%, 60.0%] | 0.0008 / 0.0070 / 0.0070 | 5 |
| tool-allowlist | 0.0% [0.0%, 60.0%] | 0.0% [0.0%, 60.0%] | 0.0011 / 0.0028 / 0.0028 | 5 |
| capability-token | 0.0% [0.0%, 60.0%] | 0.0% [0.0%, 60.0%] | 0.0028 / 0.0525 / 0.0525 | 5 |
| task-scope | 20.0% [0.0%, 60.0%] | 0.0% [0.0%, 60.0%] | 0.0051 / 7.5731 / 7.5731 | 5 |
| task-scope+binding | 100.0% [40.0%, 100.0%] | 0.0% [0.0%, 60.0%] | 0.0173 / 0.4649 / 0.4649 | 5 |
| task-scope+binding+budget | 100.0% [40.0%, 100.0%] | 0.0% [0.0%, 60.0%] | 0.0188 / 0.0751 / 0.0751 | 5 |
| task-scope+binding+budget+velocity | 100.0% [40.0%, 100.0%] | 0.0% [0.0%, 60.0%] | 0.0362 / 0.1535 / 0.1535 | 5 |
| deny-all | 100.0% [40.0%, 100.0%] | 100.0% [40.0%, 100.0%] | 0.0007 / 0.0017 / 0.0017 | 5 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.
