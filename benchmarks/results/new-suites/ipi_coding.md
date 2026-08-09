
Wrote JSON results to benchmarks/results/new-suites/ipi_coding.json
# Clay Seal enforcement benchmark — ipi_coding (45 tasks, 45 benign / 50 attack events)

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 8.6%] | 0.0% [0.0%, 6.7%] | 0.0005 / 0.0011 / 0.0068 | 45 |
| tool-allowlist | 0.0% [0.0%, 8.6%] | 0.0% [0.0%, 6.7%] | 0.0005 / 0.0007 / 0.0026 | 45 |
| capability-token | 0.0% [0.0%, 8.6%] | 0.0% [0.0%, 6.7%] | 0.0025 / 0.0029 / 0.0092 | 45 |
| task-scope | 100.0% [91.4%, 100.0%] | 0.0% [0.0%, 6.7%] | 0.0339 / 0.0501 / 1.0418 | 45 |
| task-scope+binding | 100.0% [91.4%, 100.0%] | 0.0% [0.0%, 6.7%] | 0.0341 / 0.0492 / 0.1017 | 45 |
| task-scope+binding+budget | 100.0% [91.4%, 100.0%] | 0.0% [0.0%, 6.7%] | 0.0362 / 0.4454 / 0.9458 | 45 |
| task-scope+binding+budget+velocity | 100.0% [91.4%, 100.0%] | 0.0% [0.0%, 7.5%] | 0.0361 / 0.0521 / 0.1119 | 40 |
| deny-all | 100.0% [91.4%, 100.0%] | 100.0% [93.3%, 100.0%] | 0.0005 / 0.0005 / 0.0014 | 45 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.
