# Clay Seal enforcement benchmark, atif (38 tasks, 282 benign / 0 attack events)

STATUS: current

```bash
python -m benchmarks.cli --dataset atif --mode ladder --ci --json benchmarks/results/new-suites/atif.json
```

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 7.9%] | 0.0004 / 0.0005 / 0.0007 | 38 |
| tool-allowlist | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 7.9%] | 0.0007 / 0.0008 / 0.0019 | 38 |
| capability-token | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 7.9%] | 0.0022 / 0.0027 / 0.0058 | 38 |
| task-scope | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 7.9%] | 0.0025 / 0.0052 / 0.0113 | 38 |
| task-scope+binding | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 7.9%] | 0.0052 / 0.0191 / 0.0463 | 38 |
| task-scope+binding+budget | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 7.9%] | 0.0074 / 0.0286 / 0.0517 | 38 |
| task-scope+binding+budget+velocity | 0.0% [0.0%, 100.0%] | 1.9% [0.0%, 6.2%] | 0.0074 / 0.0305 / 0.0677 | 19 |
| deny-all | 0.0% [0.0%, 100.0%] | 100.0% [92.1%, 100.0%] | 0.0003 / 0.0004 / 0.0005 | 38 |
| position-only-control | 0.0% [0.0%, 100.0%] | 51.6% [30.2%, 65.8%] | 0.0005 / 0.0006 / 0.0013 | 19 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.

> `position-only-control` reads nothing but an event's index in its task. It is a floor, not a defense: a rung that does not beat it is reporting the order of the corpus rather than the content of the actions.
