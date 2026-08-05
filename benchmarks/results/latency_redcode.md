# Enforcement latency — redcode (250 tasks, 10880 decisions per engine)

| Engine | p50 (us) | p95 (us) | p99 (us) | max (us) | added over previous |
| --- | --- | --- | --- | --- | --- |
| allow-all | 0.458 | 0.541 | 0.542 | 11.459 | - |
| tool-allowlist | 0.584 | 0.667 | 0.708 | 6.750 | +0.126 us |
| capability-token | 3.708 | 4.208 | 4.292 | 17.125 | +3.124 us |
| task-scope | 7.917 | 50.000 | 84.417 | 1206.167 | +4.209 us |
| task-scope+binding | 12.958 | 50.584 | 78.958 | 383.042 | +5.041 us |
| task-scope+binding+budget | 15.250 | 50.625 | 56.375 | 186.291 | +2.292 us |
| deny-all | 0.542 | 0.791 | 0.833 | 106.625 | -14.708 us |

The full stack decides in 15.2 us at p50 and 56.4 us at p99. For scale, a single LLM tool-call round trip is on the order of hundreds of milliseconds, so enforcement is roughly four orders of magnitude below the thing it gates and is not a throughput consideration for an agent. It would be one for an inline syscall filter, which is why the syscall-boundary layer is measured separately rather than extrapolated from these numbers.

Cold pass (scope compilation, cache population) over all 250 tasks: 17.7 ms, amortized once per task and excluded from the distribution above.
