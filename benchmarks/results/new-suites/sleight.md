
Wrote JSON results to benchmarks/results/new-suites/sleight.json
# Clay Seal enforcement benchmark — sleight (88 tasks, 311 benign / 328 attack events)

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 6.7%] | 0.0% [0.0%, 7.0%] | 0.0007 / 0.0013 / 0.0337 | 45 |
| tool-allowlist | 1.2% [0.0%, 3.7%] | 1.3% [0.0%, 3.8%] | 0.0005 / 0.0025 / 0.1288 | 45 |
| capability-token | 0.0% [0.0%, 6.7%] | 0.0% [0.0%, 7.0%] | 0.0024 / 0.0030 / 0.0162 | 45 |
| task-scope | 8.5% [4.4%, 13.7%] | 6.4% [2.8%, 10.8%] | 0.0162 / 0.3268 / 1.9685 | 45 |
| task-scope+binding | 8.5% [4.4%, 13.7%] | 6.4% [2.8%, 10.8%] | 0.0165 / 0.0853 / 0.2098 | 45 |
| task-scope+binding+budget | 8.5% [4.4%, 13.7%] | 6.4% [2.8%, 10.8%] | 0.0215 / 0.0997 / 0.2882 | 45 |
| task-scope+binding+budget+velocity | 8.5% [4.4%, 13.7%] | 2.8% [0.0%, 6.2%] | 0.0253 / 0.1108 / 0.3004 | 45 |
| deny-all | 100.0% [93.3%, 100.0%] | 100.0% [93.0%, 100.0%] | 0.0008 / 0.0009 / 0.0013 | 45 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.
