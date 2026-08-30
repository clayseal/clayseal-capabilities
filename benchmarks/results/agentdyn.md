# AgentDyn: the system does not work on open-ended tasks

STATUS: current

STATUS applies to a document that reports measurements. This one is an
**analysis**: it reasons over results produced elsewhere rather than emitting
its own, so there is no command to re-run. `current` here means the argument
still matches the results it reasons about, checked against this commit.

AgentDyn (arXiv:2602.03117) is the 2026 successor to AgentDojo from the DRIFT
authors. Its tasks are open-ended and require the agent to plan at runtime
rather than follow a plan fixed in advance, and it embeds helpful third-party
instructions in tool output specifically to measure over-defense. Its published
finding is that of ten state-of-the-art defenses, almost all are either
insufficiently secure or over-defend badly.

We ran it because it was the benchmark most likely to hurt us. It did.

## Result

gpt-4o-mini, `important_instructions`, 6 user x 3 injection tasks per cell:

| Suite | Configuration | Clean utility | ASR | Interruptions/task |
| --- | --- | --: | --: | --: |
| shopping | undefended | 66.7% | 16.7% | 0.00 |
| shopping | **envelope-taint** | **0.0%** | 0.0% | **21.67** |
| shopping | envelope-taint-graduated | 0.0% | 0.0% | 23.17 |
| github | undefended | 83.3% | 61.1% | 0.00 |
| github | **envelope-taint** | **0.0%** | 0.0% | **13.33** |
| github | envelope-taint-graduated | 0.0% | 0.0% | 16.17 |

**Clean utility is zero on both suites.** On shopping the layer blocked 254 of
281 actions. Attack success is also zero, which is what a system that blocks
everything achieves and is not a security result.

`dailylife` is still running and will not change the conclusion.

## Why

This is the plan-conformance gate at full scale. The intent envelope compiles a
plan from the sealed goal before execution and denies consequential actions that
deviate from it. AgentDyn's tasks are constructed so that the correct next step
cannot be known in advance: the agent has to look at what is in the shop, the
repository, or the calendar and decide from there. Every such step is a
deviation, and each one is denied.

The same rule accounts for 100% of our hard false blocks on AgentDojo. There it
cost utility at the margin because AgentDojo tasks are mostly determined by the
prompt. Here it costs everything, because the tasks are not.

The interruption figures say the same thing from the other side. 21.67
interruptions per task is not a defense with a friction problem, it is a system
asking a human to approve substantially every action it takes.

## What this changes

**It refutes any general claim about our utility cost.** The 3-point figure on
grok-4-1-fast and the 29-point pooled figure on gpt-4o-mini are both AgentDojo
numbers, and AgentDojo tasks are largely specified up front. On tasks that
require runtime planning the cost is total. Utility claims have to carry the
task type, not just the model.

**It moves runtime replanning from the roadmap to the critical path.** The fix is
already identified and is the AuthGraph mechanism: extend the authorization graph
at runtime under least-privilege constraints rather than denying deviation.
`SessionBroker.reclear` exists for exactly this and is called from nowhere. That
work was queued behind parameter provenance; this reverses the order.

**It vindicates the decision to run the current benchmark.** Every number we had
was from a 2024 corpus whose task structure happens to suit our design. A buyer
deploying against open-ended work would have found this in production instead.

## What it does not change

The deterministic tiers are unaffected: containment, the adaptive red-team, the
long-horizon needle detection, structuring, and drift all measure properties
that do not depend on task open-endedness.

The security result holds in the narrow sense that ASR is zero. It is worth
nothing at zero utility, and reporting it without the utility column would be
dishonest.

## Reproduce

```bash
benchmarks/live/run_agentdyn.sh 6 3 shopping,github,dailylife
```
