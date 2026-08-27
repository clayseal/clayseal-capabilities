# Adversarial leaderboard, agentharm (176 benign tasks x 8 attack classes)

STATUS: current

```bash
python -m benchmarks.leaderboard --dataset agentharm
```

| Engine | Overall | False-block | argument‑tampering | path‑exfiltration | unauthorized‑tool | action‑escalation | connector‑substitution | fragmented‑overspend | goal‑drift | in‑scope‑burst |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| allow-all | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% | 0% |
| tool-allowlist | 38% | 0% | 0% | 0% | 100% | 0% | 0% | 0% | 100% | 0% |
| capability-token | 71% | 0% | 0% | 0% | 100% | 100% | 100% | 0% | 100% | 0% |
| task-scope | 86% | 0% | 0% | 100% | 100% | 100% | 100% | 0% | 100% | 0% |
| task-scope+binding | 86% | 0% | 0% | 100% | 100% | 100% | 100% | 0% | 100% | 0% |
| task-scope+binding+budget | 86% | 0% | 0% | 100% | 100% | 100% | 100% | 0% | 100% | 0% |
| deny-all | 100% | 100% | 0% | 100% | 100% | 100% | 100% | 0% | 100% | 100% |

Mean over 3 synthesis seeds (0..2); `±` is the standard deviation across seeds, omitted below 0.5 points. A cell with no `±` was identical on every seed, which is the signature of a structural result rather than a lucky draw.
