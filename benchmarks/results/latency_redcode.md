# Enforcement latency, redcode (250 tasks, 10880 decisions per engine)

| Engine | p50 (us) | p95 (us) | p99 (us) | max (us) | added over previous |
| --- | --- | --- | --- | --- | --- |
| allow-all | 0.667 | 0.708 | 0.792 | 19.708 | - |
| tool-allowlist | 0.667 | 0.792 | 0.834 | 3.209 | +0.000 us |
| capability-token | 3.583 | 5.042 | 6.167 | 209.917 | +2.916 us |
| task-scope | 8.958 | 53.750 | 70.334 | 1472.625 | +5.375 us |
| task-scope+binding | 15.083 | 56.166 | 78.667 | 606.625 | +6.125 us |
| task-scope+binding+budget | 18.875 | 66.416 | 180.833 | 5812.708 | +3.792 us |
| deny-all | 0.667 | 0.709 | 0.792 | 110.709 | -18.208 us |

STATUS: current

```bash
python -m benchmarks.latency --dataset redcode --limit 200 --repeats 20
```

> This table is the **engine ladder**, one rung at a time. The bottom row is
> not the same number as the `Guardrail` wrapper a reader installs; see
> [performance.md](performance.md), which reconciles the three measurement
> points and says which to quote.

The full ladder decides in 18.9 us at p50 and 180.8 us at p99. For scale, a single LLM tool-call round trip is on the order of hundreds of milliseconds, so enforcement is roughly four orders of magnitude below the thing it gates and is not a throughput consideration for an agent. It would be one for an inline syscall filter, which is why the syscall-boundary layer is measured separately rather than extrapolated from these numbers.

Cold pass (scope compilation, cache population) over all 250 tasks: 20.2 ms, amortized once per task and excluded from the distribution above.
