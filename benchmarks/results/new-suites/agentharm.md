
Wrote JSON results to benchmarks/results/new-suites/agentharm.json
# Clay Seal enforcement benchmark — agentharm (352 tasks, 653 benign / 652 attack events)

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 1.7%] | 0.0% [0.0%, 1.7%] | 0.0005 / 0.0007 / 0.0010 | 176 |
| tool-allowlist | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 1.7%] | 0.0007 / 0.0010 / 0.0017 | 176 |
| capability-token | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 1.7%] | 0.0029 / 0.0055 / 0.0212 | 176 |
| task-scope | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 1.7%] | 0.0040 / 0.0114 / 0.0231 | 176 |
| task-scope+binding | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 1.7%] | 0.0044 / 0.0146 / 0.0234 | 176 |
| task-scope+binding+budget | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 1.7%] | 0.0066 / 0.0265 / 0.0575 | 176 |
| task-scope+binding+budget+velocity | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 3.4%] | 0.0095 / 0.0342 / 0.1015 | 176 |
| deny-all | 100.0% [98.3%, 100.0%] | 100.0% [98.3%, 100.0%] | 0.0005 / 0.0008 / 0.0011 | 176 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.
