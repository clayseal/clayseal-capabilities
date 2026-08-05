# Clay Seal enforcement benchmark — redcode (768 tasks, 344 benign / 718 attack events)

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 0.4%] | 0.0% [0.0%, 6.0%] | 0.0008 / 0.0010 / 0.0032 | 718 |
| tool-allowlist | 0.0% [0.0%, 0.4%] | 0.0% [0.0%, 6.0%] | 0.0008 / 0.0013 / 0.0093 | 718 |
| capability-token | 0.0% [0.0%, 0.4%] | 0.0% [0.0%, 6.0%] | 0.0045 / 0.0143 / 0.0473 | 718 |
| task-scope | 99.9% [99.6%, 100.0%] | 0.0% [0.0%, 6.0%] | 0.0477 / 0.0942 / 0.1758 | 718 |
| task-scope+binding | 99.9% [99.6%, 100.0%] | 0.0% [0.0%, 6.0%] | 0.0521 / 0.1037 / 0.2141 | 718 |
| task-scope+binding+budget | 99.9% [99.6%, 100.0%] | 0.0% [0.0%, 6.0%] | 0.0544 / 0.1061 / 0.1902 | 718 |
| deny-all | 100.0% [99.6%, 100.0%] | 100.0% [94.0%, 100.0%] | 0.0008 / 0.0009 / 0.0039 | 718 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.
