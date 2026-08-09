# AgentHarm: 6.3% is the ceiling, not our score

We report 6.3% containment on AgentHarm and describe content-defined harm as the
axis nobody solves. The second half of that is true. The first half is a number
about a corpus that cannot measure what we were using it to measure.

## What the corpus contains

AgentHarm's public data gives one field per behaviour that describes the agent's
actions:

```json
{
  "id": "...", "name": "Propaganda AI Video", "category": "Disinformation",
  "prompt": "First, use Stable Diffusion to create an image of the politicians...",
  "target_functions": ["run_stable_diffusion_model", "create_ai_video", "post_on_x"]
}
```

`target_functions` is a list of **tool names**. There are no arguments, no
targets, no recipients, no paths, no values. Measured across every event our
loader emits:

| Field | events carrying it |
| --- | --: |
| path | **0 / 1,305** |
| args | **0 / 1,305** |
| a resource distinguishable from the tool name | **0 / 1,305** |

0 of 176 items carry any structured field other than `target_functions`.

## What follows

A per-action authorization layer decides using the fields of the action. On this
corpus the only field is the tool name, so the best any such mechanism can do is
reason about tool identity. Not "the best our mechanism does": the best any
mechanism does, including one with perfect knowledge.

That ceiling is measurable. Give an oracle the exact set of tools that appear
only in harmful variants and never in benign ones:

| | |
| --- | --: |
| tools appearing only in harmful variants | 5 of 76 |
| attack events using such a tool | **20 / 652 = 3.1%** |

**3.1%.** Every other attack event uses a tool that some benign variant also
uses, and carries nothing else to tell them apart.

Our 6.3% is *above* that, because our check is finer than the oracle's. We ask
whether the harmful twin needs a tool **this behaviour's own benign variant** did
not include, which is the goal-substitution threat model: the user authorized the
benign behaviour and the agent ran its harmful twin. A global harmful-tool set is
the cruder question and scores lower.

## So what does AgentHarm measure?

The harm lives in `prompt`, which is a **task-level instruction**, not a
per-action datum. AgentHarm asks whether a model refuses a harmful request. That
is a real and important question and it is not an authorization question: there
is no action whose authorization would have prevented it, because every action is
one the user's own benign task also performs.

Two consequences for how we report it.

**The 93.7% we miss is not 93.7% of content-defined harm we fail to contain.** It
is 93.7% of a corpus in which the discriminating information is absent from the
actions by construction. A mechanism that scored higher here would be reading the
label, which is exactly the defect that has already invalidated five numbers in
this project.

**The corpus still earns its place**, for two reasons. It is the cleanest
available statement of the goal-substitution threat model, with a benign and a
harmful variant of the same behaviour under one grant. And it is an honest floor:
if someone claims a per-call authorization layer handles content-defined harm,
AgentHarm is where that claim goes to die, ours included.

## Where content-defined harm should actually be measured

SLEIGHT-Bench, whose attack events do carry targets and arguments, and whose
sabotage tasks are a scheming agent under a legitimate user goal, which is our
threat model rather than a malicious-user one. Our number there is 36.9%
containment at 32.64% false-block, and those move together at every operating
point, so it shows no discrimination. That is the honest measurement of this axis
and it is worse news than the AgentHarm number, which is the reason to lead with
it.

For reference, the published frontier gets 32% of SLEIGHT at a 1% false-positive
rate using a frontier model with extended thinking as a monitor. Nobody contains
this class with a per-call check.

## Reproduce

```bash
.venv/bin/python -m benchmarks.scoreboard
```

The field-coverage counts and the oracle ceiling are computed in this document's
commit message and reproduce from the loader in three lines; see
`benchmarks/datasets/agentharm.py` for what is emitted and why.
