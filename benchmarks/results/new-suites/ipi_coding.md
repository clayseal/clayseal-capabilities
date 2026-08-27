# Clay Seal enforcement benchmark, ipi_coding (45 tasks, 45 benign / 50 attack events)

STATUS: current

```bash
python -m benchmarks.cli --dataset ipi_coding --mode ladder --ci --json benchmarks/results/new-suites/ipi_coding.json
```

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 8.6%] | 0.0% [0.0%, 6.7%] | 0.0005 / 0.0008 / 0.0022 | 45 |
| tool-allowlist | 0.0% [0.0%, 8.6%] | 0.0% [0.0%, 6.7%] | 0.0008 / 0.0010 / 0.4145 | 45 |
| capability-token | 0.0% [0.0%, 8.6%] | 0.0% [0.0%, 6.7%] | 0.0028 / 0.0031 / 0.0095 | 45 |
| task-scope | 100.0% [91.4%, 100.0%] | 0.0% [0.0%, 6.7%] | 0.0362 / 0.1112 / 1.0126 | 45 |
| task-scope+binding | 100.0% [91.4%, 100.0%] | 0.0% [0.0%, 6.7%] | 0.0327 / 0.0484 / 0.1034 | 45 |
| task-scope+binding+budget | 100.0% [91.4%, 100.0%] | 0.0% [0.0%, 6.7%] | 0.0328 / 0.0474 / 0.0502 | 45 |
| task-scope+binding+budget+velocity | 100.0% [91.4%, 100.0%] | 0.0% [0.0%, 7.5%] | 0.0385 / 0.0565 / 0.1158 | 40 |
| deny-all | 100.0% [91.4%, 100.0%] | 100.0% [93.3%, 100.0%] | 0.0005 / 0.0006 / 0.0049 | 45 |
| position-only-control | 100.0% [91.4%, 100.0%] | 0.0% [0.0%, 7.5%] | 0.0007 / 0.0010 / 0.0020 | 40 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.

> `position-only-control` reads nothing but an event's index in its task. It is a floor, not a defense: a rung that does not beat it is reporting the order of the corpus rather than the content of the actions.
