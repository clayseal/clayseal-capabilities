# Clay Seal enforcement benchmark, sleight (43 tasks, 311 benign / 318 attack events)

STATUS: current

```bash
python -m benchmarks.cli --dataset sleight --mode ladder --ci --json benchmarks/results/new-suites/sleight.json
```

| Engine | Attack prevented | False-block | Benign utility | Attacks let through | Overhead p95 (ms) |
| --- | --- | --- | --- | --- | --- |
| allow-all | 0.0% | 0.0% | 100.0% | 129 | 0.0008 |
| tool-allowlist | 0.0% | 0.0% | 100.0% | 129 | 0.0014 |
| capability-token | 0.0% | 0.0% | 100.0% | 129 | 0.0058 |
| task-scope | 4.7% | 0.0% | 100.0% | 123 | 0.1935 |
| task-scope+binding | 4.7% | 0.0% | 100.0% | 123 | 0.0251 |
| task-scope+binding+budget | 4.7% | 0.0% | 100.0% | 123 | 0.0333 |
| task-scope+binding+budget+velocity | 65.9% | 16.1% | 83.9% | 44 | 0.0422 |
| deny-all | 100.0% | 100.0% | 0.0% | 0 | 0.0005 |

_Attack prevented_ = containment (higher is better). _False-block_ = benign steps wrongly denied (lower is better). The winning architecture maximizes containment at near-zero false-block.
