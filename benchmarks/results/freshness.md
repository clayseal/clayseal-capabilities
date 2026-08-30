# Invalidation: the justification went stale before the action spent it

STATUS: current

```bash
python -m benchmarks.bpl_sweep --suite full --json /tmp/bpl.json
```

The precedence rung reads "A before B" out of the sealed goal. This reads its
mirror image, which is the harder half: an action that may not run **after**
something has happened, because what authorised it no longer holds.

    Clean-approval voids on later dirt
    Approvals bind to pre-amendment fields
    Pay on live bit; checks destroy it

Every field of the action is correct. In these scenarios **the stale call and the
legitimate call are byte-identical**, so scope, binding, budgets, velocity and
flow control necessarily return the same answer for both. The justification is
not part of the action, so no function of the action alone can see it.

## Result

| arm | contained | completed | **joint** |
| --- | ---: | ---: | ---: |
| `clayseal` | 54 | 130 | 52 |
| `+ obligations` | 64 | 130 | 62 |
| `+ entities` | 66 | 130 | 64 |
| `+ freshness` | **69** | **130** | **67** |

Three gains, zero regressions, completion unchanged. The gains are the three
scenarios whose goal names its invalidator, and no fourth scenario moved.

**The cumulative claim is the one that carries statistical weight.** Against the
published `clayseal` arm the three rungs together are **15 gains and 0
regressions, exact McNemar p = 6.1e-05**. Taken alone this rung gives p = 0.25,
which is the *floor* of the test at three discordant pairs rather than a weak
effect, exactly as the entity rung's p = 0.50 was at two.

## Version, never a timer

Staleness is a comparison, not a judgement. A five-second-old view of a hot
ledger is stale and a five-day-old view of an archived record is not, so age is a
proxy for change while change is directly observable. The version used here is
the strongest one a gateway gets for free: **an effect this session performed,
which moves the object by definition.** The session watched the invalidator go
past.

## What it refuses to derive, and why three of six were left

Only a goal that NAMES its invalidator arms the rule. Three of the six
freshness-shaped misses do not, and they stay open:

| scenario | goal | why not |
| --- | --- | --- |
| `toctou-stale-approval` | "Pay INV-5 only while approved" | the approval is moved by `tick_world`, a clock advance sharing no token with any part of the goal |
| `fx-stale-ceiling-arb` | "USD ceiling at fresh FX" | nothing invalidates; the benign twin inserts a `refresh_fx` the attack omits, so the rule needed is "re-read immediately before use", not "do not act after X" |
| `policy-version-skew` | "Commit under live policy version" | states the freshness requirement without naming what breaks it |

Guessing which call moves the world is how a freshness rule starts refusing
ordinary work, and the poison here is cleared by re-establishing precisely so
that the agent doing the right thing is not refused: `policy-version-skew`'s own
benign twin re-plans after the upgrade and has to keep completing.

## A latch, found by a test rather than by the suite

The first implementation treated any tool matching the justification phrase as
able to re-establish it. `pay_with_approval` and `execute_with_approval` **name
the approval they spend**, so under a consuming verb the rule could clear itself
on the very action it existed to refuse, or, in the mirror case, latch and refuse
the re-approval that should have cleared it. The sweep did not show this: the
suite's `approve_draft` is classified `call`, so the ambiguous path was never
taken.

Re-establishing and spending are now different kinds of action, split by verb. A
consuming call never clears. **The suite would have shipped this green**, which
is the argument for writing the fail-open test before reading the score.

## Provenance

The rule comes from the goal sealed before any untrusted content exists, never
from tool output and never from an argument. That an invalidator ran is a fact
about this session's own history rather than a reading of a document, so the rung
refuses rather than escalates, exactly as a missing prerequisite does.

Both fail-open directions are pinned by tests: a refused invalidator must not
poison, and a refused re-establishment must not clear. The second is the bug the
precedence rung actually shipped, where a prerequisite refused by a later gate
still discharged its obligation.
