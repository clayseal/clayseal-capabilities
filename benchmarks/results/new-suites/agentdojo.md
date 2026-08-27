# Clay Seal enforcement benchmark, agentdojo (77 tasks, 215 benign / 77 attack events)

STATUS: current

```bash
python -m benchmarks.cli --dataset agentdojo --mode ladder --ci --json benchmarks/results/new-suites/agentdojo.json
```

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 3.9%] | 0.0% [0.0%, 3.9%] | 0.0004 / 0.0004 / 0.0008 | 77 |
| tool-allowlist | 77.9% [67.5%, 87.0%] | 0.0% [0.0%, 3.9%] | 0.0007 / 0.0008 / 0.0015 | 77 |
| capability-token | 77.9% [67.5%, 87.0%] | 0.0% [0.0%, 3.9%] | 0.0017 / 0.0033 / 0.0084 | 77 |
| task-scope | 77.9% [67.5%, 87.0%] | 0.0% [0.0%, 3.9%] | 0.0023 / 0.0301 / 0.0417 | 77 |
| task-scope+binding | 100.0% [96.1%, 100.0%] | 0.0% [0.0%, 3.9%] | 0.0066 / 0.0393 / 0.0939 | 77 |
| task-scope+binding+budget | 100.0% [96.1%, 100.0%] | 0.0% [0.0%, 3.9%] | 0.0070 / 0.0461 / 0.0768 | 77 |
| task-scope+binding+budget+velocity | 100.0% [96.1%, 100.0%] | 0.0% [0.0%, 3.9%] | 0.0107 / 0.0476 / 0.0871 | 77 |
| deny-all | 100.0% [96.1%, 100.0%] | 100.0% [96.1%, 100.0%] | 0.0005 / 0.0005 / 0.0009 | 77 |
| position-only-control | 75.3% [64.9%, 84.4%] | 37.2% [27.0%, 45.1%] | 0.0007 / 0.0009 / 0.0017 | 77 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.

> **Uncalibrated:** task-scope+binding+budget+velocity found no attack-free task to calibrate on and fell back to a built-in constant. The row is that constant's behaviour, not a limit learned from this corpus's traffic.

> `position-only-control` reads nothing but an event's index in its task. It is a floor, not a defense: a rung that does not beat it is reporting the order of the corpus rather than the content of the actions.
