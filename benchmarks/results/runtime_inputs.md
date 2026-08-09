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

**Available but not wired.** The information exists at runtime and nothing plumbs
it.

| input | mechanism | status |
| --- | --- | --- |
| the acting principal | `deputy.py`, delegation boundary | `Action.meta` can carry it and nothing populates it |

Any multi-agent orchestrator knows which sub-agent issued a call; that is the one
thing it cannot not know. So the delegation result is a **wiring** gap rather
than an information gap, and closing it means passing a principal the runtime
already has. Until that happens the 100% is not deployable, and it should be
quoted as "measured, pending integration".

**Not available at all.** The input cannot be produced without already having the
answer.

| input | mechanism | why |
| --- | --- | --- |
| a clean run of the same task | twin corridor (`sealed_plan` under `assess(reference=...)`) | you either have not run the task honestly yet, or you have, and then you did not need the check |

Exactly one caller in the repository supplies a reference, and it is the
benchmark harness:

```
benchmarks/core/detector_eval.py:242   det.assess(a, reference=b)
agentauth/capabilities/broker.py:617   self.detector.assess(self._trajectory)
```

So the twin corridor's SLEIGHT containment, 94.4%, is unreachable by the shipped
system. In deployment the same corpus scores the population tiers only, which is
0 to 5.6%.

The obvious bridge does not fit either. The intent envelope compiles a plan from
the sealed goal before execution, but it carries tool names, verbs and resource
classes, while `compile_sealed_plan` reads the shell command strings, the heredoc
bodies and the file contents. The envelope knows the agent will run Bash. It does
not know what the command will say, and what the command says is the entire
signal.

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
   than something the operator must already possess, and it is the one
   architectural change an independent workflow separately marked ship-worthy.

The third is a design change rather than a tuning change, and it is the one worth
pursuing.
