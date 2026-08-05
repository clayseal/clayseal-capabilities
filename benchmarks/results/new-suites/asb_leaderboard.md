# Adversarial leaderboard — asb (51 benign tasks x 8 attack classes)

| Engine | Overall | False-block | argument‑tampering | path‑exfiltration | unauthorized‑tool | action‑escalation | connector‑substitution | fragmented‑overspend | goal‑drift | in‑scope‑burst |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| allow-all | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% |
| tool-allowlist | 61% | 0% | 0% | 0% | 100% | 0% | 0% | 0% | 100% | 0% |
| capability-token | 94% | 0% | 0% | 0% | 100% | 100% | 100% | 0% | 100% | 0% |
| task-scope | 97% | 0% | 0% | 100% | 100% | 100% | 100% | 0% | 100% | 0% |
| task-scope+binding | 97% | 0% | 0% | 100% | 100% | 100% | 100% | 0% | 100% | 0% |
| task-scope+binding+budget | 97% | 0% | 0% | 100% | 100% | 100% | 100% | 0% | 100% | 0% |
| deny-all | 100% | 100% | 0% | 100% | 100% | 100% | 100% | 0% | 100% | 100% |

Cells are containment per attack class (higher better); False-block is benign steps wrongly denied (lower better).
