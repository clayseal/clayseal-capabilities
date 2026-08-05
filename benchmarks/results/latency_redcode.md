# Enforcement latency — redcode (250 tasks, 10880 decisions per engine)

| Engine | p50 (us) | p95 (us) | p99 (us) | max (us) | added over previous |
| --- | --- | --- | --- | --- | --- |
| allow-all | 0.375 | 0.417 | 0.458 | 0.792 | - |
| tool-allowlist | 0.500 | 0.583 | 0.625 | 9.459 | +0.125 us |
| capability-token | 2.750 | 3.125 | 3.208 | 90.583 | +2.250 us |
| task-scope | 31.792 | 36.958 | 56.125 | 325.792 | +29.042 us |
| task-scope+binding | 33.792 | 38.916 | 53.500 | 234.834 | +2.000 us |
| task-scope+binding+budget | 34.875 | 41.500 | 69.333 | 288.125 | +1.083 us |
| deny-all | 0.416 | 0.666 | 0.792 | 45.042 | -34.459 us |

The full stack decides in 34.9 us at p50 and 69.3 us at p99. For scale, a single LLM tool-call round trip is on the order of hundreds of milliseconds, so enforcement is roughly four orders of magnitude below the thing it gates and is not a throughput consideration for an agent. It would be one for an inline syscall filter, which is why the syscall-boundary layer is measured separately rather than extrapolated from these numbers.

Cold pass (scope compilation, cache population) over all 250 tasks: 21.4 ms, amortized once per task and excluded from the distribution above.
