# Clay Seal enforcement benchmark, asb (51 tasks, 102 benign / 2040 attack events)

STATUS: current

```bash
python -m benchmarks.cli --dataset asb --mode ladder --ci --json benchmarks/results/new-suites/asb.json
```

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 5.9%] | 0.0% [0.0%, 5.9%] | 0.0003 / 0.0004 / 0.0005 | 51 |
| tool-allowlist | 100.0% [94.1%, 100.0%] | 0.0% [0.0%, 5.9%] | 0.0008 / 0.0009 / 0.0010 | 51 |
| capability-token | 100.0% [94.1%, 100.0%] | 0.0% [0.0%, 5.9%] | 0.0015 / 0.0019 / 0.0065 | 51 |
| task-scope | 100.0% [94.1%, 100.0%] | 0.0% [0.0%, 5.9%] | 0.0008 / 0.0017 / 0.0051 | 51 |
| task-scope+binding | 100.0% [94.1%, 100.0%] | 0.0% [0.0%, 5.9%] | 0.0010 / 0.0022 / 0.0058 | 51 |
| task-scope+binding+budget | 100.0% [94.1%, 100.0%] | 0.0% [0.0%, 5.9%] | 0.0013 / 0.0036 / 0.0108 | 51 |
| task-scope+binding+budget+velocity | 100.0% [94.1%, 100.0%] | 0.0% [0.0%, 5.9%] | 0.0018 / 0.0052 / 0.0167 | 51 |
| deny-all | 100.0% [94.1%, 100.0%] | 100.0% [94.1%, 100.0%] | 0.0004 / 0.0005 / 0.0005 | 51 |
| position-only-control | 100.0% [94.1%, 100.0%] | 0.0% [0.0%, 5.9%] | 0.0006 / 0.0011 / 0.0020 | 51 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.

> **Uncalibrated:** task-scope+binding+budget+velocity found no attack-free task to calibrate on and fell back to a built-in constant. The row is that constant's behaviour, not a limit learned from this corpus's traffic.

> `position-only-control` reads nothing but an event's index in its task. It is a floor, not a defense: a rung that does not beat it is reporting the order of the corpus rather than the content of the actions.
