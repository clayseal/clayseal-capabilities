# Adversarial leaderboard — agentharm (176 benign tasks x 8 attack classes)

| Engine | Overall | False-block | argument‑tampering | path‑exfiltration | unauthorized‑tool | action‑escalation | connector‑substitution | fragmented‑overspend | goal‑drift | in‑scope‑burst |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| allow-all | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% |
| tool-allowlist | 38% | 0% | 0% | 0% | 100% | 0% | 0% | 0% | 100% | 0% |
| capability-token | 71% | 0% | 0% | 0% | 100% | 100% | 100% | 0% | 100% | 0% |
| task-scope | 86% | 0% | 0% | 100% | 100% | 100% | 100% | 0% | 100% | 0% |
| task-scope+binding | 86% | 0% | 0% | 100% | 100% | 100% | 100% | 0% | 100% | 0% |
| task-scope+binding+budget | 86% | 0% | 0% | 100% | 100% | 100% | 100% | 0% | 100% | 0% |
| deny-all | 100% | 100% | 0% | 100% | 100% | 100% | 100% | 0% | 100% | 100% |

Cells are containment per attack class (higher better); False-block is benign steps wrongly denied (lower better).
