# Clay Seal enforcement benchmark, bfcl (1927 tasks, 3232 benign / 0 attack events)

STATUS: current

```bash
python -m benchmarks.cli --dataset bfcl --mode ladder --ci --json benchmarks/results/new-suites/bfcl.json
```

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.2%] | 0.0008 / 0.0009 / 0.0058 | 1927 |
| tool-allowlist | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.2%] | 0.0012 / 0.0016 / 0.0069 | 1927 |
| capability-token | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.2%] | 0.0030 / 0.0086 / 0.0827 | 1927 |
| task-scope | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.2%] | 0.0075 / 0.0445 / 0.2543 | 1927 |
| task-scope+binding | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.2%] | 0.0218 / 0.0962 / 0.4134 | 1927 |
| task-scope+binding+budget | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.2%] | 0.0302 / 0.1365 / 0.5916 | 1927 |
| task-scope+binding+budget+velocity | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.3%] | 0.0302 / 0.1277 / 0.4803 | 964 |
| deny-all | 0.0% [0.0%, 100.0%] | 100.0% [99.8%, 100.0%] | 0.0006 / 0.0009 / 0.0020 | 1927 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.
