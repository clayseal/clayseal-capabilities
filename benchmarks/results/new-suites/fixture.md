# Clay Seal enforcement benchmark, fixture (4 tasks, 7 benign / 5 attack events)

STATUS: current

```bash
python -m benchmarks.cli --dataset fixture --mode ladder --ci --json benchmarks/results/new-suites/fixture.json
```

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 75.0%] | 0.0% [0.0%, 75.0%] | 0.0012 / 0.0069 / 0.0069 | 4 |
| tool-allowlist | 20.0% [0.0%, 42.9%] | 0.0% [0.0%, 75.0%] | 0.0014 / 0.0037 / 0.0037 | 4 |
| capability-token | 40.0% [0.0%, 85.7%] | 0.0% [0.0%, 75.0%] | 0.0029 / 0.0144 / 0.0144 | 4 |
| task-scope | 60.0% [0.0%, 100.0%] | 0.0% [0.0%, 75.0%] | 0.0168 / 0.2816 / 0.2816 | 4 |
| task-scope+binding | 80.0% [25.0%, 100.0%] | 0.0% [0.0%, 75.0%] | 0.0141 / 0.1542 / 0.1542 | 4 |
| task-scope+binding+budget | 100.0% [25.0%, 100.0%] | 0.0% [0.0%, 75.0%] | 0.0278 / 9.6766 / 9.6766 | 4 |
| task-scope+binding+budget+velocity | 100.0% [25.0%, 100.0%] | 0.0% [0.0%, 75.0%] | 0.0219 / 0.0911 / 0.0911 | 4 |
| deny-all | 100.0% [25.0%, 100.0%] | 100.0% [25.0%, 100.0%] | 0.0006 / 0.0013 / 0.0013 | 4 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.
