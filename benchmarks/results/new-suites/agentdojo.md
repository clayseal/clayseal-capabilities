# Clay Seal enforcement benchmark, agentdojo (77 tasks, 215 benign / 77 attack events)

STATUS: current

```bash
python -m benchmarks.cli --dataset agentdojo --mode ladder --ci --json benchmarks/results/new-suites/agentdojo.json
```

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 3.9%] | 0.0% [0.0%, 3.9%] | 0.0005 / 0.0007 / 0.0011 | 77 |
| tool-allowlist | 77.9% [67.5%, 87.0%] | 0.0% [0.0%, 3.9%] | 0.0009 / 0.0015 / 0.0046 | 77 |
| capability-token | 77.9% [67.5%, 87.0%] | 0.0% [0.0%, 3.9%] | 0.0035 / 0.0052 / 0.0090 | 77 |
| task-scope | 77.9% [67.5%, 87.0%] | 0.0% [0.0%, 3.9%] | 0.0034 / 0.0589 / 0.1741 | 77 |
| task-scope+binding | 100.0% [96.1%, 100.0%] | 0.0% [0.0%, 3.9%] | 0.0112 / 0.1052 / 0.4887 | 77 |
| task-scope+binding+budget | 100.0% [96.1%, 100.0%] | 0.0% [0.0%, 3.9%] | 0.0146 / 0.2258 / 0.6116 | 77 |
| task-scope+binding+budget+velocity | 100.0% [96.1%, 100.0%] | 0.0% [0.0%, 3.9%] | 0.0178 / 0.1036 / 0.3192 | 77 |
| deny-all | 100.0% [96.1%, 100.0%] | 100.0% [96.1%, 100.0%] | 0.0007 / 0.0010 / 0.0018 | 77 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.
