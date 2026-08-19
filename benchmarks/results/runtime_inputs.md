# Does the mechanism have a runtime input?

A benchmark hands a mechanism whatever it asks for. A deployment does not. This
is the check that separates a result from a result-shaped thing, and it is not
the same question as the attribution check already applied everywhere
("does the ladder below allow every arm?"). That one asks whether the benchmark
measures the right rung. This one asks whether the rung can run at all.

The test is whether the input can be **produced by the running system**, or only
by **already knowing the answer**.

## The three tiers

**Available and wired.** The live `SessionBroker` holds it today.

| input | mechanisms that need it |
| --- | --- |
| `action.args`, path | path scope, protected zones, argument binding |
| the sealed goal | intent envelope, replan shape judge, declassification |
| declared mandate scope | every scope rung |
| egress policy | destination binding |
| value and call budgets | aggregate volume |
| wall clock | mandate expiry, velocity windows |
| running trajectory | drift, trajectory detector population tiers |
| tool OUTPUT observations | confidentiality flow, parameter provenance |

Tool outputs deserve a note: the broker itself does not see them, but
`benchmarks/live/broker_defense.py` intercepts every tool result in the execution
loop and calls `observe_output`. That is a real integration point that a
deployment can build, and the flow mechanism's numbers rest on it.

**Available but not wired. FIXED.** The acting principal is now read from
`action.meta["principal"]` and checked in `SessionBroker._floor` before anything
else, because an action nobody signed for is the confused deputy's best disguise
and must fail closed. `delegation_envelopes` carries the credential each
principal presented. A session with no delegation configured is a pass-through,
so every existing number is unchanged.

**Not available at all. FIXED by changing the input.** The corridor needed a
clean run of the same task, which a deployment never has: you either have not run
the task honestly yet, or you have, and then you did not need the check.

The intent envelope does not bridge it. It carries tool names, verbs and resource
classes, while `compile_sealed_plan` reads shell command strings, heredoc bodies
and file contents. The envelope knows the agent will run Bash; it does not know
what the command will say, and what it says is the entire signal.

**Commit-then-reveal supplies a reference the deployment does have**: the actions
the agent SAID it would take, sealed before it takes any. A declaration is the
same shape of object and the agent produces it. `SessionBroker.declared_plan`
carries it and the detector receives it as the reference.

Measured on the case that matters:

| | result |
| --- | --- |
| declared honestly, executed honestly | no flags |
| **declared honestly, then sabotaged** | **`destination 'net:s3:exfil-bucket' not in sealed plan`** |
| declared the sabotage up front | passes the corridor |

The third row is the honest limit. An agent willing to declare its sabotage
defeats the corridor, because the corridor only asks whether execution matched
the declaration. What it buys is that the attacker's destination is then in
**static text available before anything runs**, which is a far easier object to
judge than a trajectory, and it is why the declaration should itself be checked
against the sealed goal.

None means no declaration and the corridor stays off, so an existing caller is
unchanged.

## Why SLEIGHT makes this trap easy

Most corpora hand you a task and its attack. SLEIGHT hands you a task, its
attack, and **a paired clean run of the same task**. That third thing is a
generous gift and it is the one production never sends. A mechanism can consume
it without anyone noticing, because nothing in the harness distinguishes "input
the corpus provides" from "input a deployment provides".

## What would make the corridor deployable

Three ways to obtain a reference that a deployment actually has:

1. **A prior clean run.** Some workflows genuinely repeat; most do not.
2. **Shadow execution.** Real, and it doubles cost.
3. **Commit-then-reveal.** The agent declares its intended commands before
   running them, and the seal is taken from the declaration rather than from a
   past run. This makes the reference something the agent **produces** rather
   than something the operator must already possess.

**Shipped.** `SessionBroker.declared_plan` is the reference; declaration is
checked against the sealed goal (`check_declaration_against_goal`) and fails
closed before any side effect. Sealed-goal egress includes destinations inside
benign Write/Bash bodies (not only `event.path`). Measured on SLEIGHT
(`python -m benchmarks.commit_then_reveal`):

| Arm | Contained |
| --- | --: |
| honest declare, then sabotage (corridor) | 97.7% |
| declare sabotage up front (goal check) | 27.9% |
| no declaration (corridor off) | population only |
| combined when agent must declare | 97.7% |

The goal-check arm fell from an inflated ~47% after body-surface enrichment
removed false ``goal names none`` hits on same-destination content sabotage.
27.9% is the true novel-egress / suspect-callee rate. Content-only sabotage that
reuses in-goal destinations still passes the goal check and is caught only when
the agent declared honestly (corridor). See
`benchmarks/results/commit_then_reveal.md`.
