# Clay Seal enforcement benchmark — redcode (768 tasks, 344 benign / 718 attack events)

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 0.4%] | 0.0% [0.0%, 6.0%] | 0.0004 / 0.0005 / 0.0005 | 718 |
| tool-allowlist | 0.0% [0.0%, 0.4%] | 0.0% [0.0%, 6.0%] | 0.0006 / 0.0007 / 0.0008 | 718 |
| capability-token | 0.0% [0.0%, 0.4%] | 0.0% [0.0%, 6.0%] | 0.0029 / 0.0033 / 0.0042 | 718 |
| task-scope | 99.9% [99.6%, 100.0%] | 0.0% [0.0%, 6.0%] | 0.0354 / 0.0442 / 0.0696 | 718 |
| task-scope+binding | 99.9% [99.6%, 100.0%] | 0.0% [0.0%, 6.0%] | 0.0359 / 0.0445 / 0.0810 | 718 |
| task-scope+binding+budget | 99.9% [99.6%, 100.0%] | 0.0% [0.0%, 6.0%] | 0.0361 / 0.0449 / 0.0672 | 718 |
| deny-all | 100.0% [99.6%, 100.0%] | 100.0% [94.0%, 100.0%] | 0.0004 / 0.0005 / 0.0005 | 718 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.
