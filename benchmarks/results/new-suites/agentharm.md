# Clay Seal enforcement benchmark — agentharm (176 tasks, 653 benign / 652 attack events)

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 1.7%] | 0.0% [0.0%, 1.7%] | 0.0004 / 0.0004 / 0.0005 | 176 |
| tool-allowlist | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 1.7%] | 0.0005 / 0.0006 / 0.0006 | 176 |
| capability-token | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 1.7%] | 0.0020 / 0.0030 / 0.0032 | 176 |
| task-scope | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 1.7%] | 0.0022 / 0.0044 / 0.0055 | 176 |
| task-scope+binding | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 1.7%] | 0.0028 / 0.0055 / 0.0065 | 176 |
| task-scope+binding+budget | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 1.7%] | 0.0046 / 0.0112 / 0.0131 | 176 |
| deny-all | 100.0% [98.3%, 100.0%] | 100.0% [98.3%, 100.0%] | 0.0004 / 0.0004 / 0.0005 | 176 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.
