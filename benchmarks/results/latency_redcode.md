# Enforcement latency — redcode (250 tasks, 10880 decisions per engine)

| Engine | p50 (us) | p95 (us) | p99 (us) | max (us) | added over previous |
| --- | --- | --- | --- | --- | --- |
| allow-all | 0.459 | 0.541 | 0.583 | 6.750 | - |
| tool-allowlist | 0.625 | 0.667 | 0.709 | 6.208 | +0.166 us |
| capability-token | 3.125 | 4.084 | 4.667 | 140.334 | +2.500 us |
| task-scope | 9.292 | 64.333 | 128.083 | 1942.583 | +6.167 us |
| task-scope+binding | 12.500 | 57.000 | 95.459 | 1632.625 | +3.208 us |
| task-scope+binding+budget | 13.042 | 49.541 | 76.625 | 726.000 | +0.542 us |
| deny-all | 0.458 | 0.541 | 0.667 | 83.917 | -12.584 us |

The full stack decides in 13.0 us at p50 and 76.6 us at p99. For scale, a single LLM tool-call round trip is on the order of hundreds of milliseconds, so enforcement is roughly four orders of magnitude below the thing it gates and is not a throughput consideration for an agent. It would be one for an inline syscall filter, which is why the syscall-boundary layer is measured separately rather than extrapolated from these numbers.

Cold pass (scope compilation, cache population) over all 250 tasks: 16.5 ms, amortized once per task and excluded from the distribution above.
