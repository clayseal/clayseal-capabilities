# Clay Seal enforcement benchmark — asb (51 tasks, 102 benign / 2040 attack events)

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 5.9%] | 0.0% [0.0%, 5.9%] | 0.0004 / 0.0004 / 0.0005 | 51 |
| tool-allowlist | 100.0% [94.1%, 100.0%] | 0.0% [0.0%, 5.9%] | 0.0005 / 0.0006 / 0.0007 | 51 |
| capability-token | 100.0% [94.1%, 100.0%] | 0.0% [0.0%, 5.9%] | 0.0015 / 0.0016 / 0.0017 | 51 |
| task-scope | 100.0% [94.1%, 100.0%] | 0.0% [0.0%, 5.9%] | 0.0015 / 0.0017 / 0.0047 | 51 |
| task-scope+binding | 100.0% [94.1%, 100.0%] | 0.0% [0.0%, 5.9%] | 0.0017 / 0.0020 / 0.0046 | 51 |
| task-scope+binding+budget | 100.0% [94.1%, 100.0%] | 0.0% [0.0%, 5.9%] | 0.0022 / 0.0036 / 0.0101 | 51 |
| deny-all | 100.0% [94.1%, 100.0%] | 100.0% [94.1%, 100.0%] | 0.0004 / 0.0005 / 0.0005 | 51 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.
