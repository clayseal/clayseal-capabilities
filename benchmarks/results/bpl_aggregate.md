# Business-process-logic: aggregate abuse on real data

STATUS: superseded

> **STATUS: superseded.** Retired on 2026-08-29. The figures below were never
> re-derived, carry no reproduce command, and are cited by no document in this
> repository. The BPL results the README quotes is now in
> [bpl_head_to_head.md](bpl_head_to_head.md), which is stamped `current`.
>
> Kept rather than deleted, because a number that was once published should stay
> readable with its correction attached.

> No command was recorded for this file, so its numbers cannot be
> re-derived from it. `unverified` says that nobody has checked them, which
> is the honest claim; `current` would be vouching for a run nobody can
> reproduce. See the provenance section of [README.md](README.md).


The threat class most prompt-injection benchmarks do not measure: a sequence
where every individual action is authorized (right tool, right action, in-scope
path, argument that matches an authorized call) but the composite violates a
business rule. The canonical case is sub-threshold splitting, the "two $999
payments" that each pass every per-call check yet together cross a ceiling.

## Why this is the differentiator

A per-call defense decides one action at a time. By construction it cannot see an
aggregate. Every published defense that gates a single tool call (tool filters,
capability checks, argument binding, prompt-injection detectors) is structurally
blind to this class. Only a stateful rung that threads a task's calls through a
cumulative ledger can catch it. That is where a new system is decisively SOTA
rather than incrementally better, because the frontier is not weak here, it is
absent.

## The honest path to this result

This number was not free. Three findings on the way, each recorded so the claim
is not overstated:

1. The `fragmented-overspend` synthesis fired on zero wired external datasets
   (tau2, agentdojo). It needs per-task value/budget annotations that only the
   bundled `fixture` loader set. The flagship claim rested on a synthetic toy.
2. Annotating the AgentDojo banking loader with a usd ceiling made the attack
   fire, but it was caught at 38% by the per-call rungs, so the budget rung added
   nothing. The generic transform fabricated attacker payees and amounts that
   trip binding, so it was not testing the aggregate property at all.
3. The faithful fix: replay a benign AUTHORIZED transfer (exact tool, resource,
   action, args) enough times to cross the ceiling. Each call passes every
   per-call rung; only the cumulative sum trips the budget. This is the real
   individually-authorized aggregate abuse.

## Result: AgentDojo banking, offline replay, faithful transform

| Engine | fragmented-overspend | false-block |
|---|--:|--:|
| tool-allowlist | 38% | 0% |
| capability-token | 38% | 0% |
| task-scope | 38% | 0% |
| task-scope+binding | 38% | 0% |
| task-scope+binding+budget | **100%** | 0% |
| deny-all | 100% | 100% |

The per-call rungs plateau at 38 percent (the fabricated-fallback cases, where a
task has no authorized transfer to replay). The remaining 62 percent are
individually-authorized overspends that only the stateful budget rung catches.
The rung lifts containment from 38 to 100 percent at 0 percent false-block. On
the same run goal-drift and action-escalation are contained at 100 percent from
the capability rung up.

The synthetic fixture shows the same separation in isolation: fragmented-overspend
is caught only by the budget rung (100 percent) and by no rung below it.

## What this establishes and what is still open

Establishes: the aggregate/sub-threshold class is caught on a real benchmark, at
zero friction, by a rung that per-call defenses structurally lack. This is the
business-process-logic differentiator, no longer only a synthetic claim.

Open:
- `in-scope-burst` (a fully authorized read repeated into a scanning/exfil burst)
  is the aggregate class that even the budget rung does not catch, only the
  behavioral trajectory detector does. Not yet measured on real data
  (`--mode detector`). This is the next differentiator to prove.
- The `ulb_creditcard` fraud corpus (present, unregistered) is the natural
  at-scale home for value-splitting and would move this from one suite to a
  dedicated benchmark.
