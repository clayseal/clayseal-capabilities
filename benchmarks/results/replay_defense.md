# Replay defense: the lock is right, the failure modes were not

STATUS: current

Produced by `python -m benchmarks.stress_replay`. A commit token authorizes
exactly ONE irreversible side effect, and `UsedTokenStore` is the single place
that property lives. Everything proved in [commit_totality.md](commit_totality.md)
is conditional on it: if `mark_used` returns "new" twice, a one-shot
authorization becomes a standing grant until expiry, and **nothing above the
token re-checks it.**

| attack | before | after |
| --- | --- | --- |
| RACE — 64 concurrent presentations | **ok** | ok |
| OUTAGE — backend unreachable | raised out of the verifier | denies with a reason |
| HOSTILE_INPUT — token_id from a parsed token | 1 raised | ok |
| SCALING — cost per mark vs live set | **12.4x** growth, O(N²) | 0.9x, flat |

## The positive: the concurrency is correct

Sixty-four threads synchronised on a barrier, all presenting the same token at
once. **Exactly one won.** `InMemoryUsedTokenStore` holds a lock across the
check-and-set, so there is no TOCTOU window, and the distributed stores use the
right primitives for the same reason, Redis `SET NX PX`, DynamoDB conditional
put on `attribute_not_exists`. That is the hard part of a replay store and it was
already right.

## Defect 1, a store outage propagated the backend's exception

`RedisUsedTokenStore.mark_used` is a bare `client.set(...)`;
`DynamoDBUsedTokenStore` re-raises any non-conditional `ClientError`. So a
partition sent `ConnectionError` / `TimeoutError` straight out of
`verify_commit_token`, through `AgentAuthCapabilityLayer`, to the caller.

This was **not** fail-open, and that is worth stating plainly before the fix:
verification never returned True on a store failure. But the shape was wrong for
two reasons. It forces every integrator to implement the deny themselves, and
the store is explicitly documented as a seam users bring their own
implementation for, and the first integrator who wraps the call in a broad
`except` converts a partition into whatever their fallback does.

Single-use is the one property with no second line of defence, so the decision
belongs in the verifier, once. It now returns
`(False, "commit token replay store unavailable: ConnectionError")`.

**Deliberately not configurable.** Offering a fail-open switch on a replay store
is a footgun, and a caller who genuinely wants to trade replay exposure for
availability already has a supported way to say so: pass no store, and inherit
the documented exposure explicitly rather than from an outage.

## Defect 2, eviction was O(N²), and attacker-inflatable

`_evict` rebuilt a list over **every** entry on **every** `mark_used`. Measured
per-call cost against the live set:

| tokens marked | per call |
| --- | ---: |
| 2,000 | 32.5 µs |
| 20,000 | **402.8 µs** |

A 12.4x rise on traffic whose cost should be flat, and the live set is
attacker-inflatable: issuing tokens is cheap, and each one makes every subsequent
authorization slower for everyone. Replay defense becomes the slowest thing in
the request path precisely when the system is busiest.

Replaced with a min-heap keyed on expiry, so eviction touches only entries that
have genuinely expired, amortised O(log N), and idle traffic costs nothing.
After: **0.92 µs early, 0.79 µs late**, a ratio of 0.9.

The subtlety the heap introduces, and the test that pins it: re-marking a token
after its first entry expired leaves a stale heap entry behind, and popping that
must not delete the live record. Without the `self._seen.get(tid) == expires_at`
guard the token would become replayable exactly once per eviction pass, a
worse bug than the one being fixed.

**This is the same defect as the confidentiality accumulator**, which is red in
`test_flow_invariants.py` right now: an unbounded structure walked in full on
every call. Two components, one mistake, and it is worth looking for a third.

## Defect 3, a non-hashable token_id raised

`token_id` is `str()`-coerced by `from_dict`, so this was not reachable through
the parse path, but the store is public API. Now coerced at the boundary.

## Residual, stated

- **The distributed stores are still untested against a live backend.** The
  outage behaviour is verified with a fake that raises, which is exactly what
  `redis-py` does on a partition, but TTL semantics, clock skew between
  instances, and DynamoDB's lazy TTL deletion (AWS documents "typically within
  48 hours") are not exercised here. Lazy deletion is safe in the direction that
  matters: an item lingering past its TTL causes extra denials, never extra
  allows, and the verifier rejects on expiry before consulting the store anyway.
- **`_ttl_ms` floors at 1 ms** for an already-expired token. Unreachable today
  because expiry is checked before the store, but it is a coupling worth
  remembering if that order ever changes.
- **No test covers two processes.** The in-memory store's own docstring warns it
  only defends within one process; that warning is correct and unverified.

## Reproduce

```bash
python -m benchmarks.stress_replay --threads 64 --tokens 20000
pytest python/tests/test_replay_defense.py -q
```
