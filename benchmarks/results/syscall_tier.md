# Tier 4, syscall boundary (iVisor trace replay)

STATUS: current

Replay of captured iVisor fd-3 traces through demo/clayseal-ivisor capability evaluator (envelope / egress / task-scope / BPL budget). Not a live sandbox run. Scenarios 05/06 may be non-events on fd-3 by design and are scored as documented limits, not failures.

**Pass rate: 100.0%** (8/8).

| scenario | events | iVisor deny | Clay deny | layers | pass | reason |
|---|---:|---:|---:|---|---|---|
| 01-cred-exfil | 4 | 1 | 1 | egress | yes | contained via egress |
| 02-persistence | 6 | 3 | 3 | task-scope | yes | contained via task-scope |
| 03-reverse-shell | 4 | 1 | 1 | egress | yes | contained via egress |
| 04-dns-tunnel | 7 | 4 | 0 | - | yes | contained via ivisor-floor |
| 05-host-escape | 3 | 0 | 0 | - | yes | syscall-floor scenario; ivisor_denies=0, clay_denies=0 (non-event on fd-3 is expected) |
| 06-audit-evasion | 3 | 0 | 0 | - | yes | syscall-floor scenario; ivisor_denies=0, clay_denies=0 (non-event on fd-3 is expected) |
| 07-beaconing | 23 | 0 | 7 | budget[BPL] | yes | contained via budget[BPL] |
| 08-exfil-allowed-channel | 19 | 0 | 6 | budget[BPL] | yes | contained via budget[BPL] |
