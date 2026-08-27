# Clay Seal enforcement benchmark, tau2 (2545 tasks, 14842 benign / 0 attack events)

STATUS: current

```bash
python -m benchmarks.cli --dataset tau2 --mode ladder --ci --json benchmarks/results/new-suites/tau2.json
```

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.1%] | 0.0006 / 0.0007 / 0.0008 | 2545 |
| tool-allowlist | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.1%] | 0.0009 / 0.0011 / 0.0013 | 2545 |
| capability-token | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.1%] | 0.0040 / 0.0062 / 0.0205 | 2545 |
| task-scope | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.1%] | 0.0050 / 0.0123 / 0.0592 | 2545 |
| task-scope+binding | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.1%] | 0.0086 / 0.0293 / 0.0639 | 2545 |
| task-scope+binding+budget | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.1%] | 0.0106 / 0.0411 / 0.1209 | 2545 |
| task-scope+binding+budget+velocity | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.1%] | 0.0144 / 0.0508 / 0.1290 | 1273 |
| deny-all | 0.0% [0.0%, 100.0%] | 100.0% [99.9%, 100.0%] | 0.0006 / 0.0008 / 0.0009 | 2545 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.
