# Clay Seal enforcement benchmark, mcp_attack (5 tasks, 9 benign / 5 attack events)

STATUS: current

```bash
python -m benchmarks.cli --dataset mcp_attack --mode ladder --ci --json benchmarks/results/new-suites/mcp_attack.json
```

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 60.0%] | 0.0% [0.0%, 60.0%] | 0.0005 / 0.0018 / 0.0018 | 5 |
| tool-allowlist | 20.0% [0.0%, 60.0%] | 0.0% [0.0%, 60.0%] | 0.0010 / 1.7082 / 1.7082 | 5 |
| capability-token | 40.0% [0.0%, 80.0%] | 0.0% [0.0%, 60.0%] | 0.0019 / 0.0069 / 0.0069 | 5 |
| task-scope | 40.0% [0.0%, 80.0%] | 0.0% [0.0%, 60.0%] | 0.0037 / 1.4688 / 1.4688 | 5 |
| task-scope+binding | 100.0% [40.0%, 100.0%] | 0.0% [0.0%, 60.0%] | 0.0090 / 0.0535 / 0.0535 | 5 |
| task-scope+binding+budget | 100.0% [40.0%, 100.0%] | 0.0% [0.0%, 60.0%] | 0.0127 / 0.0475 / 0.0475 | 5 |
| task-scope+binding+budget+velocity | 100.0% [40.0%, 100.0%] | 0.0% [0.0%, 60.0%] | 0.0185 / 0.0505 / 0.0505 | 5 |
| deny-all | 100.0% [40.0%, 100.0%] | 100.0% [40.0%, 100.0%] | 0.0005 / 0.0009 / 0.0009 | 5 |
| position-only-control | 100.0% [40.0%, 100.0%] | 44.4% [28.6%, 50.0%] | 0.0008 / 0.0020 / 0.0020 | 5 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.

> **Uncalibrated:** task-scope+binding+budget+velocity found no attack-free task to calibrate on and fell back to a built-in constant. The row is that constant's behaviour, not a limit learned from this corpus's traffic.

> `position-only-control` reads nothing but an event's index in its task. It is a floor, not a defense: a rung that does not beat it is reporting the order of the corpus rather than the content of the actions.
