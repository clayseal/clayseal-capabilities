# Clay Seal enforcement benchmark — agentharm (176 tasks, 653 benign / 652 attack events)

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 1.7%] | 0.0% [0.0%, 1.7%] | 0.0005 / 0.0008 / 0.0010 | 176 |
| tool-allowlist | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 1.7%] | 0.0010 / 0.0013 / 0.0017 | 176 |
| capability-token | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 1.7%] | 0.0028 / 0.0065 / 0.0453 | 176 |
| task-scope | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 1.7%] | 0.0036 / 0.0291 / 0.3743 | 176 |
| task-scope+binding | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 1.7%] | 0.0045 / 0.0209 / 0.1632 | 176 |
| task-scope+binding+budget | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 1.7%] | 0.0060 / 0.0448 / 0.3492 | 176 |
| deny-all | 100.0% [98.3%, 100.0%] | 100.0% [98.3%, 100.0%] | 0.0005 / 0.0009 / 0.0449 | 176 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.
