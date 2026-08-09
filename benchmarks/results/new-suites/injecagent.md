
Wrote JSON results to benchmarks/results/new-suites/injecagent.json
# Clay Seal enforcement benchmark — injecagent (1054 tasks, 1054 benign / 1598 attack events)

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 0.3%] | 0.0% [0.0%, 0.3%] | 0.0004 / 0.0005 / 0.0005 | 1054 |
| tool-allowlist | 99.9% [99.8%, 100.0%] | 0.0% [0.0%, 0.3%] | 0.0006 / 0.0007 / 0.0008 | 1054 |
| capability-token | 99.9% [99.8%, 100.0%] | 0.0% [0.0%, 0.3%] | 0.0012 / 0.0020 / 0.0026 | 1054 |
| task-scope | 99.9% [99.8%, 100.0%] | 0.0% [0.0%, 0.3%] | 0.0008 / 0.0043 / 0.0081 | 1054 |
| task-scope+binding | 99.9% [99.8%, 100.0%] | 0.0% [0.0%, 0.3%] | 0.0013 / 0.0050 / 0.0087 | 1054 |
| task-scope+binding+budget | 99.9% [99.8%, 100.0%] | 0.0% [0.0%, 0.3%] | 0.0018 / 0.0118 / 0.0255 | 1054 |
| task-scope+binding+budget+velocity | 99.9% [99.8%, 100.0%] | 0.0% [0.0%, 0.3%] | 0.0023 / 0.0178 / 0.0589 | 1054 |
| deny-all | 100.0% [99.7%, 100.0%] | 100.0% [99.7%, 100.0%] | 0.0005 / 0.0008 / 0.0010 | 1054 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.
