# Clay Seal enforcement benchmark, toolemu (5 tasks, 10 benign / 5 attack events)

STATUS: current

```bash
python -m benchmarks.cli --dataset toolemu --mode ladder --ci --json benchmarks/results/new-suites/toolemu.json
```

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 2.6%] | 0.0003 / 0.0004 / 0.0005 | 116 |
| tool-allowlist | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 2.6%] | 0.0005 / 0.0006 / 0.0008 | 116 |
| capability-token | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 2.6%] | 0.0021 / 0.0029 / 0.0030 | 116 |
| task-scope | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 2.6%] | 0.0028 / 0.0050 / 0.0058 | 116 |
| task-scope+binding | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 2.6%] | 0.0032 / 0.0057 / 0.0074 | 116 |
| task-scope+binding+budget | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 2.6%] | 0.0048 / 0.0106 / 0.0133 | 116 |
| task-scope+binding+budget+velocity | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 5.2%] | 0.0052 / 0.0131 / 0.0194 | 58 |
| deny-all | 0.0% [0.0%, 100.0%] | 100.0% [97.4%, 100.0%] | 0.0003 / 0.0003 / 0.0004 | 116 |
| position-only-control | 0.0% [0.0%, 100.0%] | 39.4% [33.6%, 44.4%] | 0.0004 / 0.0005 / 0.0009 | 58 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.

> `position-only-control` reads nothing but an event's index in its task. It is a floor, not a defense: a rung that does not beat it is reporting the order of the corpus rather than the content of the actions.
