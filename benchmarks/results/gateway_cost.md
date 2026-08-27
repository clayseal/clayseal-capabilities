# What one authorization costs

STATUS: current

```bash
python -m benchmarks.gateway_cost
```

Measured at the `Guardrail` boundary, the wrapper the README documents,
against a policy compiled from a document. `benchmarks.latency` measures
the engine floor instead; the two are different questions.

| measurement | value |
| --- | --- |
| decision, small argument | **34.1 us** (29,331/sec, n=20,000) |
| decision, 16 KB argument | 206.5 us (4,842/sec, n=2,000) |
| cost at call 3500+ vs call 0-500 | ratio **1.0** |
| import `clayseal.capabilities` | 2.5 ms above a 19.4 ms interpreter |
| memory, idle session | 11.7 KB |
| memory, per decision | 1182 bytes (**unbounded**, see docs/TRAJECTORY_WINDOW.md) |

Per-call medians across the session, in buckets of 500: [31.08, 31.04, 31.0, 31.04, 31.13, 31.08, 31.04, 31.08] us.

A ratio near 1.0 is the claim: per-call cost does not grow with session
length. The absolute microseconds are machine-specific and the ratio is not.
