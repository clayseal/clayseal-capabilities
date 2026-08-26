# What the gateway decides while one of its components is broken

STATUS: current

```bash
python -m benchmarks.stress_faults
```

Healthy baseline: a benign payment is `allow`, an out-of-scope read is `deny`.

| seam | class | benign action | out-of-scope action | verdict |
| --- | --- | --- | --- | --- |
| `value_budget.reserve` | enforcement | raised | deny | ok |
| `value_budget.commit` | enforcement | allow | deny | ok |
| `value_budget.would_allow` | enforcement | allow | deny | ok |
| `value_budget.remaining` | enforcement | allow | deny | ok |
| `scope.is_expired` | enforcement | raised | raised | ok |
| `egress.check` | enforcement | allow | deny | ok |
| `egress.check_with_provenance` | enforcement | raised | deny | ok |
| `egress.binds` | enforcement | allow | deny | ok |
| `provenance.check_destination` | enforcement | allow | deny | ok |
| `provenance.is_grounded` | enforcement | allow | deny | ok |
| `sensitivity.is_sensitive` | enforcement | allow | deny | ok |
| `sensitivity.sends_its_arguments` | enforcement | allow | deny | ok |
| `grants.allows_resource` | enforcement | allow | deny | ok |
| `grants.allows_destination` | enforcement | allow | deny | ok |
| `grants.allows_shape` | enforcement | allow | deny | ok |
| `flow.check` | enforcement | allow | deny | ok |
| `flow.observe` | advisory | allow | deny | ok |
| `provenance.record_observation` | advisory | allow | deny | ok |
| `provenance.trusted_candidates` | advisory | allow | deny | ok |
| `session.adopt` | advisory | allow | deny | ok |
| `grants.consume` | advisory | allow | deny | ok |
| `decision_log.append` | bookkeeping | allow | deny | ok |
| `decision_log.durability` | bookkeeping | allow | deny | ok |
| `metrics.record_action` | bookkeeping | allow | deny | ok |
| `metrics.record_prevented` | bookkeeping | allow | deny | ok |
| `metrics.record_monitor_trigger` | bookkeeping | allow | deny | ok |

26 seam(s) behaved as classified, 0 skipped, **0 did not**.

No broken component turned a refusal into an allow, and no bookkeeping
failure changed a decision. An attacker who can make a component fail gains
nothing by doing it.

## The four defects this found

All four are the same shape: a component with no authority over a decision was
able to prevent one.

| seam | class | what it did | now |
| --- | --- | --- | --- |
| `decision_log.append` | bookkeeping | an audit write that failed took down the gateway | decision returned, gap counted |
| `metrics.record_action` | bookkeeping | a metrics backend going away took down the gateway | counted, decision unchanged |
| `metrics.record_prevented` | bookkeeping | same, on the refusal path | counted |
| `provenance.trusted_candidates` | advisory | a retry HINT turned a completed DENY into an exception | hint dropped, decision stands |

`unrecorded_decisions` and `telemetry_failures` count what was lost. Neither is
swallowed: an unlogged decision is an unauditable one and a deployment should
alert on the count, which is the same reasoning `DecisionLog.durability` already
applies to records evicted without reaching a sink.

## Two things the probe itself got wrong first

**Its verdict rule was weaker than its claim.** The bookkeeping rule checked only
that a broken component did not turn a refusal into an ALLOW. A crash is not an
allow, so `metrics.record_prevented` raising on every refusal passed as `ok`.
Tightening the rule to "must not reach the caller as an exception" surfaced it
immediately. This is the same failure as the path differential that excluded the
population its worst bug was in: a probe written by the author of the thing it
probes inherits that author's idea of what counts as broken.

**Six seams were reported `skipped`, and a skipped seam in a table of green ones
reads as covered.** Two were frozen dataclasses refusing attribute assignment;
`object.__setattr__` reaches them. The other four were method names guessed
rather than read off the objects. Coverage went from 5 seams to 26.

## What the enforcement column says

Sixteen enforcement seams broken one at a time, and **not one of them turns a
refusal into an allow**. Where a fault reaches the caller it does so as an
exception rather than an authorization, which is second best to a clean denial
and is not an escape.

That is the property worth stating plainly: an attacker who can make a component
of this gateway fail gains nothing by doing it. Making the ledger time out, the
provenance graph raise, or the audit sink fill up does not widen what the agent
may do.
