# Idempotence: the sixth axis, and a complete blind spot

Send the same authorized action twice. The double-charge, the double-refund, the
payroll bonus paid twice, the ticket refunded to two cards.

Every field is correct on both calls, because the second **is** the first: same
tool, same resource, same verb, same arguments, same target. The first was
authorized and the second is identical to it, so nothing judging an action in
isolation can tell them apart.

## The gap, measured

Appending one verbatim duplicate of a tau2 task's last effect call:

| rung | contained |
| --- | --: |
| tool-allowlist | 0 / 2,412 |
| capability-token | 0 / 2,412 |
| task-scope | 0 / 2,412 |
| task-scope+binding | 0 / 2,412 |
| task-scope+binding+budget | 0 / 2,412 |
| task-scope+binding+budget+velocity | 0 / 2,412 |

**Zero.** Not a rate to improve, a question no rung asks.

It is none of the axes already built. Not volume, because one duplicate is not a
burst and velocity contains none of it. Not target, because the target is
identical and correct. Not sequence, because no sensitive value flows. Not
content, because the content is exactly what was authorized. Not principal,
because the same agent acts.

## The mechanism was already here

`clayseal/capabilities/commit.py` mints single-use commit tokens and
`used_token_store.py` is the seam that makes single-use hold across processes.
Both ship, both have unit tests, and no benchmark produced a number for either.

That is the fourth time this shape has appeared: velocity before `burst.py`,
confidentiality before `flow.py`, delegation before `deputy.py`, and now commit
tokens. A mechanism ships, no corpus can test it, so it reports nothing.

## Result

400 tau2 sessions. Four arms, because the first alone is satisfied by refusing
every repeat.

| arm | result |
| --- | --: |
| **replay** (same token, already consumed) refused | **100%** (400/400) |
| **legitimate repeat** (same call, fresh token) allowed | **100%** (400/400) |
| ladder below | 800 allowed, **0 blocked** |
| **second instance** refused | **0%** (0/400) |

The legitimate arm is what makes the first one mean something. tau2 telecom
really does call `set_line_data_mode` and grant permissions repeatedly, so a
mechanism that refused all repeats would score 100% above and be useless.

### The distinguishing sweep

Containment must be flat at one duplicate, or this is burst detection renamed.

| duplicates | commit token | velocity |
| --: | --: | --: |
| 1 | **100%** | 0.0% |
| 2 | 100% | 0.0% |
| 3 | 100% | 0.0% |

Velocity contains none of it at any count, which is the axis being distinct
rather than argued to be.

## The second-instance arm, and what it does and does not say

`InMemoryUsedTokenStore` is process-local. A token consumed on one instance is
invisible to every other, so across two instances it refuses **0 of 400**.

**That is a property of the dev default, not a hole in the system**, and an
earlier version of this document overstated it. `verify_commit_token` already
refuses outright when `is_production()` and no store is configured:

    "commit token replay store required in production
     (configure CLAYSEAL_COMMIT_TOKEN_REDIS_URL or pass used_token_store)"

`RedisUsedTokenStore` and `DynamoDBUsedTokenStore` both ship, and
`load_used_token_store_from_env` resolves either from the environment. So the
production path fails closed and the shared implementations exist.

The arm stays because the in-memory store is what a benchmark reaches for by
reflex, and because this is the session-scoped ledger shape for the third time
after `principal_ledger` and `PrincipalVelocity`. What it measures is the cost of
defaulting through the seam rather than configuring it.

## Reproduce

```bash
.venv/bin/python -m benchmarks.idempotence --corpus tau2 --limit 400 \
  --json benchmarks/results/idempotence_tau2.json
```
