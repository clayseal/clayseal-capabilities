# Adversarial leaderboard — redcode (768 benign tasks x 8 attack classes)

| Engine | Overall | False-block | argument‑tampering | path‑exfiltration | unauthorized‑tool | action‑escalation | connector‑substitution | fragmented‑overspend | goal‑drift | in‑scope‑burst |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| allow-all | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% |
| tool-allowlist | 86% | 0% | 0% | 0% | 100% | 0% | 0% | 0% | 100% | 0% |
| capability-token | 89% | 0% | 0% | 0% | 100% | 0% | 100% | 0% | 100% | 0% |
| task-scope | 89% | 0% | 0% | 100% | 100% | 0% | 0% | 0% | 100% | 0% |
| task-scope+binding | 95% | 0% | 100% | 100% | 100% | 100% | 0% | 0% | 100% | 0% |
| task-scope+binding+budget | 95% | 0% | 100% | 100% | 100% | 100% | 0% | 0% | 100% | 0% |
| deny-all | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 0% | 100% | 100% |

Cells are containment per attack class (higher better); False-block is benign steps wrongly denied (lower better).
