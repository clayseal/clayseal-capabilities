# Enforcement latency — redcode (250 tasks, 10880 decisions per engine)

| Engine | p50 (us) | p95 (us) | p99 (us) | max (us) | added over previous |
| --- | --- | --- | --- | --- | --- |
| allow-all | 0.375 | 0.458 | 0.500 | 2.834 | - |
| tool-allowlist | 0.625 | 1.000 | 1.125 | 26.459 | +0.250 us |
| capability-token | 5.042 | 5.750 | 6.875 | 60.084 | +4.417 us |
| task-scope | 34.000 | 60.666 | 75.208 | 279.959 | +28.958 us |
| task-scope+binding | 37.458 | 65.250 | 81.375 | 230.500 | +3.458 us |
| task-scope+binding+budget | 39.875 | 69.958 | 93.125 | 201.417 | +2.417 us |
| deny-all | 0.750 | 0.792 | 0.875 | 26.875 | -39.125 us |

The full stack decides in 39.9 us at p50 and 93.1 us at p99. For scale, a single LLM tool-call round trip is on the order of hundreds of milliseconds, so enforcement is roughly four orders of magnitude below the thing it gates and is not a throughput consideration for an agent. It would be one for an inline syscall filter, which is why the syscall-boundary layer is measured separately rather than extrapolated from these numbers.

Cold pass (scope compilation, cache population) over all 250 tasks: 26.1 ms, amortized once per task and excluded from the distribution above.
