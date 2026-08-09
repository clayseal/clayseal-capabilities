
Wrote JSON results to benchmarks/results/new-suites/agent_threat_bench.json
# Clay Seal enforcement benchmark — agent_threat_bench (24 tasks, 24 benign / 6 attack events)

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 50.0%] | 0.0% [0.0%, 12.5%] | 0.0005 / 0.0023 / 0.0025 | 24 |
| tool-allowlist | 0.0% [0.0%, 50.0%] | 0.0% [0.0%, 12.5%] | 0.0007 / 0.0012 / 0.0018 | 24 |
| capability-token | 0.0% [0.0%, 50.0%] | 0.0% [0.0%, 12.5%] | 0.0049 / 0.0068 / 0.0119 | 24 |
| task-scope | 100.0% [50.0%, 100.0%] | 0.0% [0.0%, 12.5%] | 0.0768 / 0.3068 / 1.6588 | 24 |
| task-scope+binding | 100.0% [50.0%, 100.0%] | 0.0% [0.0%, 12.5%] | 0.0177 / 0.0961 / 0.1074 | 24 |
| task-scope+binding+budget | 100.0% [50.0%, 100.0%] | 0.0% [0.0%, 12.5%] | 0.0175 / 0.0463 / 0.0573 | 24 |
| task-scope+binding+budget+velocity | 100.0% [50.0%, 100.0%] | 0.0% [0.0%, 20.0%] | 0.0249 / 0.0455 / 0.0499 | 15 |
| deny-all | 100.0% [50.0%, 100.0%] | 100.0% [87.5%, 100.0%] | 0.0005 / 0.0007 / 0.0012 | 24 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.
