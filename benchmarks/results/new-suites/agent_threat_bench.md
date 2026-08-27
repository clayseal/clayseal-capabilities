# Clay Seal enforcement benchmark, agent_threat_bench (24 tasks, 24 benign / 6 attack events)

STATUS: current

```bash
python -m benchmarks.cli --dataset agent_threat_bench --mode ladder --ci --json benchmarks/results/new-suites/agent_threat_bench.json
```

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 50.0%] | 0.0% [0.0%, 12.5%] | 0.0005 / 0.0016 / 0.0020 | 24 |
| tool-allowlist | 0.0% [0.0%, 50.0%] | 0.0% [0.0%, 12.5%] | 0.0007 / 0.0018 / 0.1726 | 24 |
| capability-token | 0.0% [0.0%, 50.0%] | 0.0% [0.0%, 12.5%] | 0.0042 / 0.0064 / 0.0103 | 24 |
| task-scope | 100.0% [50.0%, 100.0%] | 0.0% [0.0%, 12.5%] | 0.0604 / 0.1271 / 1.1894 | 24 |
| task-scope+binding | 100.0% [50.0%, 100.0%] | 0.0% [0.0%, 12.5%] | 0.0104 / 0.0367 / 0.0372 | 24 |
| task-scope+binding+budget | 100.0% [50.0%, 100.0%] | 0.0% [0.0%, 12.5%] | 0.0167 / 0.0386 / 0.0980 | 24 |
| task-scope+binding+budget+velocity | 100.0% [50.0%, 100.0%] | 0.0% [0.0%, 20.0%] | 0.0223 / 0.0413 / 0.0444 | 15 |
| deny-all | 100.0% [50.0%, 100.0%] | 100.0% [87.5%, 100.0%] | 0.0004 / 0.0007 / 0.0009 | 24 |
| position-only-control | 100.0% [50.0%, 100.0%] | 0.0% [0.0%, 20.0%] | 0.0006 / 0.0014 / 0.0015 | 15 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.

> `position-only-control` reads nothing but an event's index in its task. It is a floor, not a defense: a rung that does not beat it is reporting the order of the corpus rather than the content of the actions.
