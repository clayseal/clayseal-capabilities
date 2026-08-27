# Clay Seal enforcement benchmark, injecagent (1054 tasks, 1054 benign / 1598 attack events)

STATUS: current

```bash
python -m benchmarks.cli --dataset injecagent --mode ladder --ci --json benchmarks/results/new-suites/injecagent.json
```

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 0.3%] | 0.0% [0.0%, 0.3%] | 0.0004 / 0.0005 / 0.0007 | 1054 |
| tool-allowlist | 99.9% [99.8%, 100.0%] | 0.0% [0.0%, 0.3%] | 0.0007 / 0.0008 / 0.0015 | 1054 |
| capability-token | 99.9% [99.8%, 100.0%] | 0.0% [0.0%, 0.3%] | 0.0015 / 0.0027 / 0.0123 | 1054 |
| task-scope | 99.9% [99.8%, 100.0%] | 0.0% [0.0%, 0.3%] | 0.0010 / 0.0072 / 0.0215 | 1054 |
| task-scope+binding | 99.9% [99.8%, 100.0%] | 0.0% [0.0%, 0.3%] | 0.0012 / 0.0046 / 0.0062 | 1054 |
| task-scope+binding+budget | 99.9% [99.8%, 100.0%] | 0.0% [0.0%, 0.3%] | 0.0018 / 0.0114 / 0.0300 | 1054 |
| task-scope+binding+budget+velocity | 99.9% [99.8%, 100.0%] | 0.0% [0.0%, 0.3%] | 0.0025 / 0.0156 / 0.0510 | 1054 |
| deny-all | 100.0% [99.7%, 100.0%] | 100.0% [99.7%, 100.0%] | 0.0004 / 0.0005 / 0.0005 | 1054 |
| position-only-control | 100.0% [99.7%, 100.0%] | 0.0% [0.0%, 0.3%] | 0.0006 / 0.0007 / 0.0008 | 1054 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.

> **Uncalibrated:** task-scope+binding+budget+velocity found no attack-free task to calibrate on and fell back to a built-in constant. The row is that constant's behaviour, not a limit learned from this corpus's traffic.

> `position-only-control` reads nothing but an event's index in its task. It is a floor, not a defense: a rung that does not beat it is reporting the order of the corpus rather than the content of the actions.
