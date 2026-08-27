# Clay Seal enforcement benchmark, atif (38 tasks, 282 benign / 0 attack events)

STATUS: current

```bash
python -m benchmarks.cli --dataset atif --mode ladder --ci --json benchmarks/results/new-suites/atif.json
```

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 7.9%] | 0.0005 / 0.0007 / 0.0030 | 38 |
| tool-allowlist | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 7.9%] | 0.0007 / 0.0009 / 0.0012 | 38 |
| capability-token | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 7.9%] | 0.0030 / 0.0047 / 0.0069 | 38 |
| task-scope | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 7.9%] | 0.0033 / 0.0074 / 0.0329 | 38 |
| task-scope+binding | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 7.9%] | 0.0107 / 0.3198 / 1.6033 | 38 |
| task-scope+binding+budget | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 7.9%] | 0.0142 / 0.1443 / 0.6763 | 38 |
| task-scope+binding+budget+velocity | 0.0% [0.0%, 100.0%] | 1.9% [0.0%, 6.2%] | 0.0167 / 0.0752 / 0.9406 | 19 |
| deny-all | 0.0% [0.0%, 100.0%] | 100.0% [92.1%, 100.0%] | 0.0008 / 0.0009 / 0.0095 | 38 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.
