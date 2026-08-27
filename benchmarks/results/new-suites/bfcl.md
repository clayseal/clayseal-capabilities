# Clay Seal enforcement benchmark, bfcl (1927 tasks, 3232 benign / 0 attack events)

STATUS: current

```bash
python -m benchmarks.cli --dataset bfcl --mode ladder --ci --json benchmarks/results/new-suites/bfcl.json
```

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.2%] | 0.0004 / 0.0004 / 0.0005 | 1927 |
| tool-allowlist | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.2%] | 0.0008 / 0.0013 / 0.0034 | 1927 |
| capability-token | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.2%] | 0.0016 / 0.0036 / 0.0154 | 1927 |
| task-scope | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.2%] | 0.0036 / 0.0107 / 0.0314 | 1927 |
| task-scope+binding | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.2%] | 0.0095 / 0.0302 / 0.0608 | 1927 |
| task-scope+binding+budget | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.2%] | 0.0142 / 0.0350 / 0.0707 | 1927 |
| task-scope+binding+budget+velocity | 0.0% [0.0%, 100.0%] | 0.0% [0.0%, 0.3%] | 0.0183 / 0.0456 / 0.1150 | 964 |
| deny-all | 0.0% [0.0%, 100.0%] | 100.0% [99.8%, 100.0%] | 0.0004 / 0.0005 / 0.0005 | 1927 |
| position-only-control | 0.0% [0.0%, 100.0%] | 42.1% [38.4%, 45.4%] | 0.0007 / 0.0009 / 0.0013 | 964 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.

> `position-only-control` reads nothing but an event's index in its task. It is a floor, not a defense: a rung that does not beat it is reporting the order of the corpus rather than the content of the actions.
