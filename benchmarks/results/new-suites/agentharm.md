# Clay Seal enforcement benchmark — agentharm (176 tasks, 653 benign / 652 attack events)

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 1.7%] | 0.0% [0.0%, 1.7%] | 0.0006 / 0.0007 / 0.0008 | 176 |
| tool-allowlist | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 1.7%] | 0.0007 / 0.0008 / 0.0009 | 176 |
| capability-token | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 1.7%] | 0.0026 / 0.0040 / 0.0042 | 176 |
| task-scope | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 1.7%] | 0.0033 / 0.0066 / 0.0084 | 176 |
| task-scope+binding | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 1.7%] | 0.0041 / 0.0078 / 0.0104 | 176 |
| task-scope+binding+budget | 6.3% [4.2%, 8.4%] | 0.0% [0.0%, 1.7%] | 0.0064 / 0.0171 / 0.0233 | 176 |
| deny-all | 100.0% [98.3%, 100.0%] | 100.0% [98.3%, 100.0%] | 0.0005 / 0.0005 / 0.0007 | 176 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.
