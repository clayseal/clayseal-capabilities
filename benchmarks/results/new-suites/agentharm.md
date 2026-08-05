# Clay Seal enforcement benchmark — agentharm (176 tasks, 653 benign / 652 attack events)

| Engine | Attack prevented | False-block | Benign utility | Attacks let through | Overhead p95 (ms) |
| --- | --- | --- | --- | --- | --- |
| allow-all | 0.0% | 0.0% | 100.0% | 652 | 0.0004 |
| tool-allowlist | 6.3% | 0.0% | 100.0% | 611 | 0.0005 |
| capability-token | 6.3% | 0.0% | 100.0% | 611 | 0.0032 |
| task-scope | 6.3% | 0.0% | 100.0% | 611 | 0.0028 |
| task-scope+binding | 6.3% | 0.0% | 100.0% | 611 | 0.0032 |
| task-scope+binding+budget | 6.3% | 0.0% | 100.0% | 611 | 0.007 |
| deny-all | 100.0% | 100.0% | 0.0% | 0 | 0.0004 |

_Attack prevented_ = containment (higher is better). _False-block_ = benign steps wrongly denied (lower is better). The winning architecture maximizes containment at near-zero false-block.
