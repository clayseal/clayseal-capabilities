# Long-trajectory evaluation: one buried attack per session, 100000 benign actions

STATUS: current

```bash
python -m benchmarks.trajectory
```

Re-derived against this commit. The previous revision was stamped `unverified`
and its title said 40 sessions of 500 actions, 20,000 judged; the harness now
runs 100000. The detection and false-alarm figures are unchanged by that, and the
title is corrected rather than left describing a smaller run.

# Long-trajectory evaluation, 200 sessions of 500 benign actions, one buried attack each

Haystack: `bfcl`. Needle: `redcode`. 100000 benign actions judged per engine.

| Engine | Needle detected | False alarms / 1k actions | Alarms per session |
| --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 1.9%] | 0.00 | 0.00 |
| tool-allowlist | 0.0% [0.0%, 1.9%] | 0.00 | 0.00 |
| capability-token | 82.0% [76.1%, 86.7%] | 0.00 | 0.00 |
| task-scope | 83.0% [77.2%, 87.6%] | 0.00 | 0.00 |
| task-scope+binding | 100.0% [98.1%, 100.0%] | 0.00 | 0.00 |
| task-scope+binding+budget | 100.0% [98.1%, 100.0%] | 0.00 | 0.00 |
| task-scope+binding+budget+velocity | 100.0% [98.1%, 100.0%] | 0.00 | 0.00 |

_Needle detected_ is per session, not per event: a session where the buried malicious action was blocked counts as caught. _False alarms per 1k actions_ is the deployability number, multiply by the session length to get what an operator sees per session, which is the last column. A per-action false-block rate that rounds to zero on a three-call benchmark can still page someone every few minutes on a real session.
