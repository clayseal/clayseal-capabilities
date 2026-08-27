# Clay Seal enforcement benchmark, advbench_agent (6 tasks, 11 benign / 6 attack events)

STATUS: current

```bash
python -m benchmarks.cli --dataset advbench_agent --mode ladder --ci --json benchmarks/results/new-suites/advbench_agent.json
```

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 50.0%] | 0.0% [0.0%, 50.0%] | 0.0004 / 0.0015 / 0.0015 | 6 |
| tool-allowlist | 16.7% [0.0%, 50.0%] | 0.0% [0.0%, 50.0%] | 0.0007 / 0.1544 / 0.1544 | 6 |
| capability-token | 16.7% [0.0%, 50.0%] | 0.0% [0.0%, 50.0%] | 0.0014 / 0.0054 / 0.0054 | 6 |
| task-scope | 66.7% [33.3%, 100.0%] | 0.0% [0.0%, 50.0%] | 0.0070 / 0.9988 / 0.9988 | 6 |
| task-scope+binding | 100.0% [50.0%, 100.0%] | 0.0% [0.0%, 50.0%] | 0.0104 / 0.0500 / 0.0500 | 6 |
| task-scope+binding+budget | 100.0% [50.0%, 100.0%] | 0.0% [0.0%, 50.0%] | 0.0183 / 0.0511 / 0.0511 | 6 |
| task-scope+binding+budget+velocity | 100.0% [50.0%, 100.0%] | 0.0% [0.0%, 50.0%] | 0.0232 / 0.0446 / 0.0446 | 6 |
| deny-all | 100.0% [50.0%, 100.0%] | 100.0% [50.0%, 100.0%] | 0.0004 / 0.0009 / 0.0009 | 6 |
| position-only-control | 100.0% [50.0%, 100.0%] | 45.5% [33.3%, 50.0%] | 0.0006 / 0.0018 / 0.0018 | 6 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.

> **Uncalibrated:** task-scope+binding+budget+velocity found no attack-free task to calibrate on and fell back to a built-in constant. The row is that constant's behaviour, not a limit learned from this corpus's traffic.

> `position-only-control` reads nothing but an event's index in its task. It is a floor, not a defense: a rung that does not beat it is reporting the order of the corpus rather than the content of the actions.
