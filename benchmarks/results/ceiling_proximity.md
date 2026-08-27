# The ceiling curve, and one escape in the ledger that answers session restart

STATUS: current

Two pieces of work: an attack pass on `principal_ledger.py`, which found and
closed a real escape, and the benchmark that was missing from the head-to-head.

## 1. The escape: reserve/commit desync

`principal_ledger.py` is the fix for the session-restart escape in
[aggregation_residual.md](aggregation_residual.md), which makes it the component
an attacker now has a reason to attack. It was also the least fuzzed code in the
enforcement floor.

The attack needs no clock control and no special capability. Only patience:

```
reserve 100 against a ceiling of 100
wait out the 300-second hold TTL
reserve 100 again          <- the first hold has been dropped, so this fits
commit both holds
```

**200 booked against a ceiling of 100, reported as nothing.** A session lasting
longer than the tool timeout is entirely ordinary.

The cause is a gap between two correct-looking decisions. `_expire_holds` drops
a hold after the TTL, which exists to stop a crashed agent shrinking its
principal's ceiling forever. `commit_hold` books from the Hold and cannot
re-check the ceiling, because the call order is authorize → act → commit and by
commit time the effect has landed. Each is defensible; together the headroom is
freed while the hold stays committable.

### Two fixes were wrong before the third

**Refusing the late commit** is the payment-industry answer (an expired
authorization cannot be captured) and it under-counts here: the effect happened,
and a ledger that declines to record it reports headroom that is already spent.
This module's own docstring rules it out, "under-counting is the failure that
lets an attack through".

**Settling the hold as spend on expiry** never under-counts and closes the
escape completely. It also re-opens the exact denial of service the TTL was
added for, and
`test_an_abandoned_hold_expires_instead_of_shrinking_the_ceiling_forever`
failed immediately. That test was right and the fix was wrong.

**Voiding** is the one that satisfies all three constraints. Expiry frees the
headroom, so the DoS stays fixed. The hold's id is remembered, and the ceiling
it was checked against is captured on the Hold itself, so `commit_hold` can
re-check at commit time. It books either way, the effect landed, and records a
breach when it no longer fits. The escape becomes visible instead of silent,
which is the standard [aggregation_residual.md](aggregation_residual.md) already
holds the mandate escapes to.

The projection has to include outstanding holds, not just booked spend. The
first version of the check compared `spent + amount` and missed its own escape:
at the moment the voided hold commits nothing is spent yet, and the replacement
reservation is still a hold, so 100 against a ceiling of 100 looked fine.

## 1b. The second escape: delegation splitting

The plan lists this axis as "unclosed by construction, and where MCP deployments
live". It was:

```
parent + 5 sub-agents, each asking for the full ceiling
-> 600 landed against a ceiling of 100
```

Every sub-agent has its own `sub`, therefore its own `principal_key`, therefore
its own ceiling. A per-delegate ceiling is not a ceiling: anyone who can spawn
sub-agents mints headroom, and spawning sub-agents is the normal mode of the
deployments this is aimed at.

Closed by `principal_chain(binding)` plus a `chain` on `PrincipalBudgetView`. A
delegate's spend is reserved and booked against **every ancestor** as well as
itself, all-or-nothing: a partial group would leave a parent's headroom held for
a delegate action that never happened, which is the denial of service the hold
TTL exists to prevent arriving by another route.

Both directions measured:

| | before | after |
| --- | ---: | ---: |
| parent + 5 delegates each asking 100 | 600 landed | **100 landed** |
| delegate spending inside the parent's remaining headroom (50, then 30, then 15) | allowed | **allowed** |
| the delegate action that would cross (a further 20) | allowed | **refused** |

**This makes the delegation chain security-critical, which it was not before.**
A delegate's spend now charges its ancestors, so a forged chain is an attack on
someone else's ceiling: name the victim as your parent and exhaust it. That is
covered because `delegation_chain` is in `AUTHORITY_FIELDS`, so
[identity_boundary.md](identity_boundary.md)'s strip already stops a claims dict
naming its own ancestors, a fix made for a different reason that this change
turned load-bearing. Chain entries are issuer-qualified for the same reason the
principal key is. Both are pinned.

### The rest of the attack surface held

`python -m benchmarks.stress_principal_ledger`, 13 axes, **0 escapes** after both
fixes:

| axis | result |
| --- | --- |
| delegation splitting (1 + 5) | 100 landed, the parent's ceiling |
| forged delegation chain | stripped; a claims dict names no ancestors |
| reserve/commit desync (TTL) | 200 booked, **1 breach reported** |
| double commit of one hold | books once |
| window boundary, early expiry | 100 of 100 still counted at t+999 of 1000 |
| idempotency key across sessions | 500 booked; reuse does not suppress |
| idempotency, amount swapped | both book; no laundering under one key |
| 32 concurrent reservations | 10 of 32 granted, exactly at the ceiling |
| torn tail on reload | 90 of 100; the truncated record is lost, the rest is not |
| re-book across a reload | idempotency survives a restart |
| sub-quantum amounts | 2,000 × 0.0001 books as 0.2000 exactly |
| absurd amounts (`1e999`, `Infinity`, `NaN`, negative, zero) | all refused, none raised |
| clock rewind | 100 of 100 still visible from an earlier `now` |

## 2. The benchmark: what 37% progress actually meant

[bpl_head_to_head.md](bpl_head_to_head.md) reports the ledger at 0 violations
against 400/400 for both published baselines, and the ledger completing 37% to
61% of requested work. **That second number was not interpretable**, because the
requested work in those scenarios is over-ceiling by construction. Refusing 40%
of a task whose whole point is to exceed a limit is the control working.
Refusing 40% of a task that stays inside the limit is the control being useless.
Nothing in the suite separated those.

`python -m benchmarks.ceiling_proximity` sweeps the ratio of benign demand to
ceiling across four demand shapes, reporting both error directions.

**False-block rate on demand that fits (ratio ≤ 1.0):**

| shape | actions that fit | ledger | allow-all | deny-all |
| --- | ---: | --- | --- | ---: |
| uniform | 140 | **0/140, 97.5% upper bound 2.6%** | 0/140 | 140/140 |
| single | 7 | **0/7, 97.5% upper bound 41.0%** | 0/7 | 7/7 |
| ramp | 140 | **0/140, 97.5% upper bound 2.6%** | 0/140 | 140/140 |
| front-loaded | 140 | **0/140, 97.5% upper bound 2.6%** | 0/140 | 140/140 |

Pooled over all four shapes: **0 of 427, 97.5% upper bound 0.9%**. The `single`
row is thin on purpose, that shape is one action per session, so seven ratios
give seven actions and its bound is correspondingly wide.

**Over-ceiling value on demand that does not fit (ratio > 1.0):**

| shape | ledger | allow-all | deny-all |
| --- | ---: | ---: | ---: |
| uniform | **held** | +1810 | held |
| single | **held** | +1810 | held |
| ramp | **held** | +1810 | held |
| front-loaded | **held** | +1810 | held |

**0 false blocks of 427 actions that fit, and 0 over-ceiling value landed**
across every shape and every ratio.

The two control rows are the point, and they are printed permanently for the
same reason `opeval.py` prints its own. Either column is trivially winnable:
`deny-all` holds every ceiling and refuses every honest action; `allow-all` never
blocks anything and lets 1,810 over-ceiling through. Only a row that wins both is
a result.

### The curve

Uniform shape, landed/ceiling:

| ratio | ledger | allow-all |
| ---: | ---: | ---: |
| 0.90 | 0.90 | 0.90 |
| 0.99 | 0.99 | 0.99 |
| 1.00 | 1.00 | 1.00 |
| 1.01 | **0.96** | 1.01 |
| 1.25 | 1.00 | 1.25 |
| 2.00 | 1.00 | 2.00 |

The ledger tracks demand exactly up to the ceiling and then flattens. So the
answer to "does the ceiling cost honest work" is no, up to the point where the
work stops being honest.

**One real utility cost, visible at ratio 1.01: the ledger lands 0.96, not
1.00.** Actions are atomic, so when the next one does not fit it is refused
whole, and up to one action's worth of headroom goes unused. That is inherent to
indivisible effects rather than a defect, and it is the honest form of the
friction claim: the cost is bounded by the largest single action, not by the
block rate.

## What this does not measure

- **One ceiling, one budget, one principal.** Key splitting and untracked tools
  are [aggregation_residual.md](aggregation_residual.md)'s territory and are
  caught by the mandate linter, not here.
- **Demand shape is synthetic.** Four shapes chosen to stress ordering, not
  drawn from traffic. The design partner's logs are what make this a
  distributional claim rather than a structural one.
- **No model.** Deterministic and offline by construction, which is the point:
  this measures the ledger, and the ledger's decisions do not depend on one.

## Reproduce

```bash
python -m benchmarks.stress_principal_ledger
python -m benchmarks.ceiling_proximity
pytest python/tests/test_principal_ledger.py benchmarks/tests/test_ceiling_proximity.py -q
```
