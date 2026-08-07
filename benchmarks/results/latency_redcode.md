# Enforcement latency — redcode (250 tasks, 10880 decisions per engine)

| Engine | p50 (us) | p95 (us) | p99 (us) | max (us) | added over previous |
| --- | --- | --- | --- | --- | --- |
| allow-all | 0.417 | 0.458 | 0.500 | 0.917 | - |
| tool-allowlist | 0.500 | 0.583 | 0.625 | 7.500 | +0.083 us |
| capability-token | 2.708 | 3.125 | 3.417 | 10.292 | +2.208 us |
| task-scope | 5.833 | 36.042 | 43.583 | 146.625 | +3.125 us |
| task-scope+binding | 9.542 | 36.458 | 42.875 | 97.708 | +3.709 us |
| task-scope+binding+budget | 12.542 | 39.542 | 48.708 | 138.584 | +3.000 us |
| deny-all | 0.375 | 0.458 | 0.500 | 2.875 | -12.167 us |

The full stack decides in 12.5 us at p50 and 48.7 us at p99. For scale, a single LLM tool-call round trip is on the order of hundreds of milliseconds, so enforcement is roughly four orders of magnitude below the thing it gates and is not a throughput consideration for an agent. It would be one for an inline syscall filter, which is why the syscall-boundary layer is measured separately rather than extrapolated from these numbers.

Cold pass (scope compilation, cache population) over all 250 tasks: 12.4 ms, amortized once per task and excluded from the distribution above.
