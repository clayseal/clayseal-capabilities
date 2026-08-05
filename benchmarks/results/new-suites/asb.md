# Clay Seal enforcement benchmark — asb (51 tasks, 102 benign / 2040 attack events)

| Engine | Attack prevented | False-block | Benign utility | Attacks let through | Overhead p95 (ms) |
| --- | --- | --- | --- | --- | --- |
| allow-all | 0.0% | 0.0% | 100.0% | 2040 | 0.0004 |
| tool-allowlist | 100.0% | 0.0% | 100.0% | 0 | 0.0006 |
| capability-token | 100.0% | 0.0% | 100.0% | 0 | 0.0015 |
| task-scope | 100.0% | 0.0% | 100.0% | 0 | 0.0007 |
| task-scope+binding | 100.0% | 0.0% | 100.0% | 0 | 0.001 |
| task-scope+binding+budget | 100.0% | 0.0% | 100.0% | 0 | 0.0018 |
| deny-all | 100.0% | 100.0% | 0.0% | 0 | 0.0004 |

_Attack prevented_ = containment (higher is better). _False-block_ = benign steps wrongly denied (lower is better). The winning architecture maximizes containment at near-zero false-block.
