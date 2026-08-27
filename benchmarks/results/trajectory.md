# Long-trajectory evaluation, 40 sessions of 500 benign actions, one buried attack each

Haystack: `bfcl`. Needle: `redcode`. 20000 benign actions judged per engine.

| Engine | Needle detected | False alarms / 1k actions | Alarms per session |
| --- | --- | --- | --- |
| allow-all | 0.0% [0.0%, 8.8%] | 0.00 | 0.00 |
| tool-allowlist | 0.0% [0.0%, 8.8%] | 0.00 | 0.00 |
| capability-token | 72.5% [57.2%, 83.9%] | 0.00 | 0.00 |
| task-scope | 75.0% [59.8%, 85.8%] | 0.00 | 0.00 |
| task-scope+binding | 100.0% [91.2%, 100.0%] | 0.00 | 0.00 |
| task-scope+binding+budget | 100.0% [91.2%, 100.0%] | 0.00 | 0.00 |

_Needle detected_ is per session, not per event: a session where the buried malicious action was blocked counts as caught. _False alarms per 1k actions_ is the deployability number, multiply by the session length to get what an operator sees per session, which is the last column. A per-action false-block rate that rounds to zero on a three-call benchmark can still page someone every few minutes on a real session.
