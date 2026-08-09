# Clay Seal enforcement benchmark — asb (51 tasks, 102 benign / 2040 attack events)

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 5.9%] | 0.0% [0.0%, 5.9%] | 0.0007 / 0.0008 / 0.0010 | 51 |
| tool-allowlist | 100.0% [94.1%, 100.0%] | 0.0% [0.0%, 5.9%] | 0.0009 / 0.0011 / 0.0012 | 51 |
| capability-token | 100.0% [94.1%, 100.0%] | 0.0% [0.0%, 5.9%] | 0.0018 / 0.0025 / 0.0058 | 51 |
| task-scope | 100.0% [94.1%, 100.0%] | 0.0% [0.0%, 5.9%] | 0.0024 / 0.0029 / 0.0117 | 51 |
| task-scope+binding | 100.0% [94.1%, 100.0%] | 0.0% [0.0%, 5.9%] | 0.0023 / 0.0068 / 0.0216 | 51 |
| task-scope+binding+budget | 100.0% [94.1%, 100.0%] | 0.0% [0.0%, 5.9%] | 0.0038 / 0.0069 / 0.0254 | 51 |
| deny-all | 100.0% [94.1%, 100.0%] | 100.0% [94.1%, 100.0%] | 0.0007 / 0.0008 / 0.0009 | 51 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.
