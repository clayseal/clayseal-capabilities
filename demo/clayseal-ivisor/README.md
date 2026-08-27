# Clay Seal × iVisor Arena

A live containment console for untrusted AI-agent workloads. It runs a roster of
attack scenarios inside iVisor's Apple Silicon sandbox and shows, in real time,
the agent's actions beside iVisor's unforgeable policy verdicts, with breakout
and behavioral-policy-limit violations blocked as they happen and mapped to MITRE
ATT&CK. Every run ends with a verifiable, hash-chained decision log.

The design goal is instrumentation, not a dashboard. Verdict lines are iVisor's
own output, verbatim. Color marks the block and nothing else. A raw fd-3 firehose
is one keystroke away so a skeptic can confirm nothing was staged.

## Why the two layers

- **iVisor** observes every syscall below the guest and writes verdicts to a file
  descriptor the guest cannot reach (`IVISOR_TRACE_FD=3`, iVisor ADR-0021). That
  stream is the one action log the agent cannot forge. It is the enforcement floor.
- **Clay Seal Capabilities** binds a sealed capability to that stream: which egress
  hosts, which writable paths, and a behavioral limit on action volume. The
  behavioral limit catches exfiltration and beaconing that ride an *allowed*
  channel, which a per-syscall allowlist cannot see.

Together: iVisor proves what the agent actually did, Clay Seal decides whether the
sealed capability permitted it, and the decision log makes the whole thing
auditable after the fact.

## Run it

Needs an Apple Silicon Mac and the iVisor repo with its guest rootfs fetched once
(`cd ~/Projects/iVisor && scripts/fetch-guest-rootfs.sh`). Use the Clay Seal
Capabilities virtualenv, which has `agentauth` installed:

```bash
cd ~/Projects/clayseal-ivisor-demo
PY=~/Projects/clayseal/.venv/bin/python

$PY arena.py live 07-beaconing          # live panelled TUI (needs rich)
$PY arena.py live all                   # the whole roster, live
$PY arena.py list                       # the roster
$PY arena.py run 07-beaconing           # one scenario, plain interleaved stream
$PY arena.py run 06-audit-evasion --audit   # + raw fd-3 firehose close
$PY arena.py all                        # plain stream for all, refresh sample traces
```

`live` is the panelled console: the agent-versus-sandbox event stream on the
left, the scenario and a live verdict tally on the right, blocks lit as they
happen. `run` is the same data as a plain interleaved stream, better for logs
and recordings. With no arguments it prints the roster and asks which to run.

The `live` view needs `rich` (`pip install rich` into the venv above). Everything
else is standard library.

## Three ways to show it

| Surface | Command | Best for |
|---|---|---|
| Live TUI | `arena.py live <id>` | showing the sandbox blocking attacks in real time |
| Plain stream | `arena.py run <id>` | logs, terminal recordings, piping |
| Containment report | `build_report.py` then publish `report.html` | a shareable, inspectable record after the fact |

### Offline replay

Each run can be re-rendered from a captured fd-3 stream, so the Clay Seal side runs
anywhere without the sandbox:

```bash
$PY arena.py replay 07-beaconing sample_traces/07-beaconing.trace
```

Scenarios 05 (host escape) and 06 (audit evasion) are best seen live: their result
is a syscall-floor denial and a non-event, neither of which lives on the fd-3
channel that replay reads.

## The roster

| # | Scenario | ATT&CK | Blocked by |
|---|---|---|---|
| 01 | Credential harvest and exfiltration | T1552.001, T1041 | iVisor egress + Clay Seal egress capability |
| 02 | Rootfs persistence (cron + library plant) | T1053.003, T1543 | iVisor floor (EROFS) + Clay Seal task-scope |
| 03 | Reverse shell / C2 callback | T1059.004, T1071 | iVisor egress |
| 04 | DNS-tunnel exfiltration | T1048, T1071.004 | iVisor DNS intercept |
| 05 | Container / host escape | T1611 | iVisor syscall floor (ENOSYS) |
| 06 | Audit-channel evasion (forge the trace) | T1562.001 | unforgeable fd-3 channel |
| 07 | Beaconing over an allowed channel | T1071, T1029 | Clay Seal behavioral limit |
| 08 | Bulk exfil over an allowed channel | T1567, T1041 | Clay Seal behavioral limit |

Scenarios 07 and 08 are the behavioral-policy-limit cases: iVisor allows every
individual connection because the destination is on the allowlist, and only the
sealed egress budget sees the pattern. That is the layer a plain syscall sandbox
cannot provide.

## The four capability layers (real Clay Seal APIs)

| Layer | Clay Seal primitive | Catches |
|---|---|---|
| Structural envelope | `monitor.TypedGoalEnvelope.assess` | verbs, tools, resource classes outside the goal |
| Egress capability | authorized host set over iVisor's DNS pin map | connections to any destination the goal did not name |
| Task-scope floor | `core.task_scope.task_scope_allows_path` | writes outside the sealed `/work` workspace |
| Behavioral limit | `call_budget.SessionCallBudget` | egress volume, i.e. beaconing and bulk exfil over allowed channels |

Every decision is recorded with `capabilities.decision_log.DecisionLog`, whose
`verify()` proves the receipt chain was not altered.

## Files

| File | Role |
|---|---|
| `arena.py` | the console: roster, live/plain run, export, fd-3 audit hatch, decision-log verify |
| `tui.py` | the panelled live TUI (rich) |
| `scenarios.py` | the 8 scenarios (premise, ATT&CK, guest agent, sealed capability) |
| `capability.py` | the sealed-capability model and builders |
| `engine.py` | parse iVisor verdicts, evaluate the four layers, write the decision log |
| `build_report.py` | turn a run export into the self-contained `report.html` |
| `report_data.json` | structured export of the last `arena.py export all` run |
| `sample_traces/` | captured fd-3 streams for offline replay |

## Notes

- All eight blocks are real and grounded in verified iVisor behavior. The exfil and
  reverse-shell connects are denied `not-allowlisted`, persistence writes fail
  `EROFS` outside the workspace, DNS-tunnel names are denied `not-allowlisted`,
  escape syscalls return `ENOSYS`, and the guest cannot open fd 3.
- iVisor's floor can be stricter than the sealed capability. Transient errno
  denials during setup are labelled operational and kept out of the policy counts.
- `~0.9µs` is iVisor's measured syscall floor (BENCHMARKS.md), shown as a real,
  cited figure rather than a fabricated per-event timing.
- `sendfile` (aarch64 syscall 71) is not yet implemented in iVisor; pip falls back
  to read/write, so it has no effect here.
```
