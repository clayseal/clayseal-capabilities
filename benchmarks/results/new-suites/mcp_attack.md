# Clay Seal enforcement benchmark, mcp_attack (5 tasks, 9 benign / 5 attack events)

STATUS: current

```bash
python -m benchmarks.cli --dataset mcp_attack --mode ladder --ci --json benchmarks/results/new-suites/mcp_attack.json
```

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 60.0%] | 0.0% [0.0%, 60.0%] | 0.0010 / 0.0054 / 0.0054 | 5 |
| tool-allowlist | 20.0% [0.0%, 60.0%] | 0.0% [0.0%, 60.0%] | 0.0012 / 0.0038 / 0.0038 | 5 |
| capability-token | 40.0% [0.0%, 80.0%] | 0.0% [0.0%, 60.0%] | 0.0027 / 0.0151 / 0.0151 | 5 |
| task-scope | 40.0% [0.0%, 80.0%] | 0.0% [0.0%, 60.0%] | 0.0049 / 2.4550 / 2.4550 | 5 |
| task-scope+binding | 100.0% [40.0%, 100.0%] | 0.0% [0.0%, 60.0%] | 0.0191 / 2.4090 / 2.4090 | 5 |
| task-scope+binding+budget | 100.0% [40.0%, 100.0%] | 0.0% [0.0%, 60.0%] | 0.0155 / 0.0789 / 0.0789 | 5 |
| task-scope+binding+budget+velocity | 100.0% [40.0%, 100.0%] | 0.0% [0.0%, 60.0%] | 0.0297 / 1.2809 / 1.2809 | 5 |
| deny-all | 100.0% [40.0%, 100.0%] | 100.0% [40.0%, 100.0%] | 0.0007 / 0.0020 / 0.0020 | 5 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.
