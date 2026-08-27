# AgentHarm, DeployableStack (current) vs stale ladder

STATUS: current

```bash
python -m benchmarks.cli --dataset agentharm --mode ladder --ci --json benchmarks/results/new-suites/agentharm.json
```

> **The ladder is an ablation; the shipped product scores higher.** `--mode stack` runs the `DeployableStack` this library actually ships, which has the intent envelope, parameter provenance, the confidentiality flow tracker and the session rules the ladder stops below: **union 55.3% (hard 30.9% / soft 24.4%)** against the ladder's 27.2%, at 0.00% false-block. Soft is a step-up, never fold it into a hard containment headline. The full product tier is in [`benchmarks/scoreboard.py`](../../scoreboard.py).

| Engine | Attack prevented | False-block | Overhead p50/p95/p99 (ms) | Tasks |
| --- | --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 1.7%] | 0.0% [0.0%, 1.7%] | 0.0004 / 0.0004 / 0.0005 | 176 |
| tool-allowlist | 5.9% [4.0%, 7.9%] | 0.0% [0.0%, 1.7%] | 0.0007 / 0.0010 / 0.0014 | 176 |
| capability-token | 27.2% [22.8%, 32.1%] | 0.0% [0.0%, 1.7%] | 0.0025 / 0.0034 / 0.0035 | 176 |
| task-scope | 27.2% [22.8%, 32.1%] | 0.0% [0.0%, 1.7%] | 0.0035 / 0.0065 / 0.0079 | 176 |
| task-scope+binding | 27.2% [22.8%, 32.1%] | 0.0% [0.0%, 1.7%] | 0.0040 / 0.0072 / 0.0133 | 176 |
| task-scope+binding+budget | 27.2% [22.8%, 32.1%] | 0.0% [0.0%, 1.7%] | 0.0053 / 0.0127 / 0.0141 | 176 |
| task-scope+binding+budget+velocity | 27.2% [22.8%, 32.1%] | 0.0% [0.0%, 3.4%] | 0.0074 / 0.0158 / 0.0179 | 176 |
| deny-all | 100.0% [98.3%, 100.0%] | 100.0% [98.3%, 100.0%] | 0.0005 / 0.0005 / 0.0005 | 176 |
| position-only-control | 27.6% [24.1%, 30.9%] | 29.4% [24.5%, 34.3%] | 0.0006 / 0.0008 / 0.0009 | 176 |

Brackets are 95% percentile bootstrap intervals resampling **tasks**, not events: events within a task share a template, so an event-level interval would be roughly sqrt(events-per-task) too narrow. _Tasks_ is the resampling unit count. Two engines whose intervals overlap are not distinguishable on this corpus.

> `position-only-control` reads nothing but an event's index in its task. It is a floor, not a defense: a rung that does not beat it is reporting the order of the corpus rather than the content of the actions.
