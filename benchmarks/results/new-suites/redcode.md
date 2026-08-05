# Clay Seal enforcement benchmark — redcode (768 tasks, 344 benign / 718 attack events)

| Engine | Attack prevented | False-block | Benign utility | Attacks let through | Overhead p95 (ms) |
| --- | --- | --- | --- | --- | --- |
| allow-all | 0.0% | 0.0% | 100.0% | 718 | 0.0004 |
| tool-allowlist | 0.0% | 0.0% | 100.0% | 718 | 0.0005 |
| capability-token | 0.0% | 0.0% | 100.0% | 718 | 0.0032 |
| task-scope | 99.9% | 0.0% | 100.0% | 1 | 0.0156 |
| task-scope+binding | 99.9% | 0.0% | 100.0% | 1 | 0.0203 |
| task-scope+binding+budget | 99.9% | 0.0% | 100.0% | 1 | 0.0223 |
| deny-all | 100.0% | 100.0% | 0.0% | 0 | 0.0004 |

_Attack prevented_ = containment (higher is better). _False-block_ = benign steps wrongly denied (lower is better). The winning architecture maximizes containment at near-zero false-block.
