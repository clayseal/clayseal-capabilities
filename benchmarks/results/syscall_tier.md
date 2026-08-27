# Tier 4, syscall boundary (iVisor trace replay)

STATUS: current

```bash
python -m benchmarks.syscall_tier
```

Replay of captured iVisor fd-3 traces through demo/clayseal-ivisor capability evaluator (envelope / egress / task-scope / BPL budget). Not a live sandbox run. Scenarios 05 and 06 attempt nothing the fd-3 channel sees, and their captured traces are byte-identical to each other: three lines of ordinary allowed activity. They used to be hardcoded to pass by scenario id, which made a 6-of-6 result read as 8/8. They are excluded from the rate now, because a replay carrying no attack is evidence of neither containment nor escape. Previously read: scenarios 05/06 may be non-events by design and are scored as documented limits, not failures.

**Pass rate: 100.0%** (6/6 scenarios that produce a syscall-level event; 2 excluded as non-events).

| scenario | events | iVisor deny | Clay deny | layers | pass | reason |
|---|---:|---:|---:|---|---|---|
| 01-cred-exfil | 4 | 1 | 1 | egress | yes | contained via egress |
| 02-persistence | 6 | 3 | 3 | task-scope | yes | contained via task-scope |
| 03-reverse-shell | 4 | 1 | 1 | egress | yes | contained via egress |
| 04-dns-tunnel | 7 | 4 | 0 | - | yes | contained via ivisor-floor |
| 05-host-escape | 3 | 0 | 0 | - | n/a | no syscall-level event to decide: ivisor_denies=0, clay_denies=0; excluded from the rate |
| 06-audit-evasion | 3 | 0 | 0 | - | n/a | no syscall-level event to decide: ivisor_denies=0, clay_denies=0; excluded from the rate |
| 07-beaconing | 23 | 0 | 7 | budget[BPL] | yes | contained via budget[BPL] |
| 08-exfil-allowed-channel | 19 | 0 | 6 | budget[BPL] | yes | contained via budget[BPL] |
