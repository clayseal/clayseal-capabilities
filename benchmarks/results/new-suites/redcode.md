
Wrote JSON results to benchmarks/results/new-suites/redcode.json
# Clay Seal enforcement benchmark, redcode (768 tasks, 344 benign / 718 attack events)

STATUS: current

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 0.4%] | 0.0% [0.0%, 6.0%] | 0.0005 / 0.0008 / 0.0109 | 718 |
| tool-allowlist | 0.0% [0.0%, 0.4%] | 0.0% [0.0%, 6.0%] | 0.0006 / 0.0011 / 0.0024 | 718 |
| capability-token | 0.0% [0.0%, 0.4%] | 0.0% [0.0%, 6.0%] | 0.0030 / 0.0052 / 0.0245 | 718 |
| task-scope | 99.9% [99.6%, 100.0%] | 0.0% [0.0%, 6.0%] | 0.0409 / 0.0925 / 0.2355 | 718 |
| task-scope+binding | 99.9% [99.6%, 100.0%] | 0.0% [0.0%, 6.0%] | 0.0419 / 0.0990 / 0.2740 | 718 |
| task-scope+binding+budget | 99.9% [99.6%, 100.0%] | 0.0% [0.0%, 6.0%] | 0.0433 / 0.0802 / 0.1435 | 718 |
| task-scope+binding+budget+velocity | 99.9% [99.6%, 100.0%] | 0.0% [0.0%, 12.0%] | 0.0440 / 0.0869 / 0.1688 | 718 |
| deny-all | 100.0% [99.6%, 100.0%] | 100.0% [94.0%, 100.0%] | 0.0005 / 0.0007 / 0.0008 | 718 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.
