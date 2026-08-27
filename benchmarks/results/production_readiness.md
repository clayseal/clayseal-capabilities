# Production readiness: the ceiling did not survive a second process

STATUS: current

Every cumulative-authorization claim in this repository was measured in one
process. No deployment runs that way, and the gap was not academic.

## 1. The blocker

Four OS processes, one ledger file, ceiling of 100:

```
ceiling   100
landed    400
VERDICT   ESCAPED
```

`PrincipalLedger` synchronises on a `threading.RLock`, which is process-local.
Each worker loaded the log, saw nothing spent, reserved, committed. It is the
same check-then-act race `reserve` already fixes for threads, one layer out.

It matters more than any other open item because it is **the session-restart
escape arriving through the process table**. `principal_ledger.py` exists to stop
an attacker getting a second ceiling by opening a second conversation; a second
gunicorn worker or k8s replica hands them one for free. The n=100 head-to-head,
the ceiling curve and the delegation fix are all single-process measurements.

The telling detail: `RedisUsedTokenStore` already exists and is documented "for
multi-instance replay defense". The replay layer had been multi-instance for a
while. The ledger carrying the headline claim had not caught up.

## 2. What it took

`SharedPrincipalLedger`. Three things have to be shared, not one, and missing any
of them leaves the hole open.

**Mutual exclusion.** A `fcntl` lock file, so the read-modify-write in `reserve`
is atomic across processes.

**Committed spend.** The in-memory index is a snapshot from load time. Every
transaction now tails the log for bytes appended by anyone else. A server process
holds one ledger for its lifetime, so "read it at startup" is the same bug as not
sharing at all, it just takes longer to show up.

**Outstanding holds.** The subtle one, and the part a shared log alone does not
fix. Two processes that each hold a reservation cannot see each other's, so both
pass the ceiling check and both commit later. Holds, voids and settlements live
in a sidecar rewritten under the same lock.

The base class gained one seam, `_transaction()`, replacing seven separate
`with self._lock:` sites, so a Redis or Postgres backend has a single thing to
override rather than seven.

| | before | after |
| --- | ---: | ---: |
| 4 processes × 100, ceiling 100 | 400 landed | **100** |
| 16 processes × 5 × 10, ceiling 100 | — | **100**, totals verified |
| uncommitted hold in another process | invisible | **blocks** |
| release in one process | never freed elsewhere | **frees** |

### Two bugs found while building it

**A load race.** `__post_init__` read the whole file and then separately stat'd
it for the offset. Anything appended between those two calls was skipped
forever, spend this process could not see, so headroom it would grant twice.
Fixed by starting at offset 0 and letting the first transaction read under the
lock, which is the only place a load is safe.

**Phantom holds, and this one hid.** `_load_sidecar` merged `self._holds` back on
top of the sidecar to preserve its own Hold objects, but after a sync
`self._holds` contains *every* process's reservations, so the merge resurrected
holds their owners had already released. Measured across 16 processes: five
phantom holds pinning 50 of a 100 ceiling, 70 landing where 100 should have.

It failed in the safe direction, which is exactly why it needed finding: the
ceiling is never breached, the system quietly refuses honest work, and every
individual decision looks correct. Nothing needed preserving, a hold created in
a transaction is written before that transaction ends, and `release` matches on
`hold_id` rather than object identity, so a caller's reference still resolves
after a sync replaces the objects.

## 3. The backend is a dependency, so it can be down

Before: a raw `PermissionError` escaped the authorization path. Fail-closed only
by accident, it takes the request down, cannot be told from a bug, and nothing
counts it.

Now `LedgerUnavailable`, with an explicit configured policy:

| `on_unavailable` | behaviour | counted |
| --- | --- | --- |
| `"deny"` (default) | refuses, with a reason naming the backend | yes |
| `"allow"` | proceeds on this process's view | yes |

There is no correct universal answer here; availability is sometimes worth more
than a ceiling. What is not acceptable is an implicit one. This repository has
already shipped six fail-opens whose whole shape was a control that stopped
applying when its input was unusual and reported success.

`allow` is never the default and is always counted. One refused action counts as
exactly one outage, `reserve` calls `spent`, which opens its own transaction,
and without re-entrancy on the failure path one action reported two, which is the
kind of inflated number an operator learns to ignore on the one metric that says
the ceiling stopped being enforced.

## 4. Operability

`ledger.health()` returns a flat, serialisable snapshot. Two fields mean the
ceiling stopped being enforced and both were recorded and surfaced nowhere:

```json
{"entries": 2, "tracked_keys": 1, "outstanding_holds": 0,
 "late_breaches": 1, "late_breach_value": "100", "unavailable": 0,
 "totals_verified": true, "cross_process": true}
```

`late_breaches` is a commit that landed after its hold was voided and no longer
fit, the spend is booked and the log is correct, but the check did not hold for
it, and that needs reconciling the same day rather than a window later.
`totals_verified` is the one that should page someone: false means the cached
totals have drifted from the log, which silently raises a ceiling.

## 5. Supervision is real, and verified not to have moved anything

`gate_with_supervision` turns a STEP_UP into a question rather than a halt. Until
it existed, every utility number for a supervised run was a **counterfactual**:
`summarize_ladder` added the step-up losses back and assumed both that a human
would have said yes and that the task then succeeded. With a resolving approver
the number becomes measured rather than assumed. That is
only worth something if the new path is identical to the old when nobody answers,
otherwise every published autonomous number came from different code.

The plan states it as W1's verification and it now runs: with `NeverApprove`
which enters the loop, asks, and is declined, verdicts, allow counts and block
counts all match the plain `gate()` path exactly. A guard test asserts the
fixture still produces a refusal, so the parity has something to prove.

## 6. The behavioural layer is already opt-in

`DeployableStack.from_goal` takes `detector=None` by default, so the trajectory
detector does not ship enabled. That is the right default and worth stating
explicitly, because on SLEIGHT it scores 100% containment by refusing 13 of 18
benign trajectories, and its false-block rate does not move under either knob.
See the strict xfail on `test_sleight_detector_twin_corridor_beats_population_floor`.

## Open

- **Single host.** `fcntl` covers multiple processes on one machine, which is the
  common deployment. Multiple hosts need the same `_transaction` seam taking a
  Redis or Postgres lock. The seam exists; the backend does not.
- **The sidecar is rewritten whole under the lock.** Fine while holds are
  TTL-bounded and few. A deployment with thousands of concurrent outstanding
  holds on one budget wants a different structure.
- **No fsync.** An OS-level crash can lose the tail of the log. The torn-tail
  path handles a partial record; it does not handle a lost one.

## Reproduce

```bash
pytest python/tests/test_shared_ledger.py benchmarks/tests/test_supervision_parity.py -q
```
