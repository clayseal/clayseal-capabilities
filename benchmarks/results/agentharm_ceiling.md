# AgentHarm: the ceiling claim was wrong, and the corpus does carry targets

STATUS: current

> **WITHDRAWN.** This document argued that 6.3% is an information-theoretic
> ceiling because no AgentHarm event carries a target. That is true of the JSON
> our loader reads and false of the benchmark. AgentHarm's grading functions,
> which are part of the benchmark and are on disk at
> `.benchmark-corpus/inspect_evals/src/inspect_evals/agentharm/benchmark/harmful_grading_functions.py`,
> assert concrete argument values: file paths, email recipients and URLs.
>
> | | harmful | benign |
> | --- | --: | --: |
> | grading functions | 52 | 52 |
> | mentioning a concrete literal anywhere (regex) | 33 (63%) | 36 (69%) |
> | asserting a target by EQUALITY (AST) | **16** | **20** |
> | both twins yield an equality target | **16** | |
> | and the harmful target DIFFERS from the benign one | **7** | |
>
> The 63% was a first-pass regex count and it overstates the yield. Most of those
> literals are substring assertions such as `"donald" in args["prompt"]`, which
> describe content rather than a target; emitting one as a target would be
> inventing an event, the defect that cost us 18 of 24 AgentThreatBench events.
>
> Under strict AST extraction of equality assertions, 16 behaviours yield a
> target on both sides and only **7** have a harmful target the benign twin's
> grant would not have included. That is roughly 31 of 652 attack events, so the
> upper bound on containment is about **6.3% to 11.1%**, assuming every one of
> them is caught.
>
> So the ceiling argument below is still void, and the correction is worth about
> five points rather than a transformation. AgentHarm remains dominated by harm
> that is defined by content rather than by target.
>
> Found by an audit agent reading the corpus against our loader. The
> field-coverage counts below remain accurate **about our loader's output** and
> are kept because they explain what the 6.3% currently measures.

## The original argument, kept for the record

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
threat model rather than a malicious-user one.

Our number there was 36.9% containment at 32.64% false-block, and auditing it
found the same defect class again. SLEIGHT ships **no mandate**: it is a
transcript-monitoring benchmark, paired attack and benign runs of a coding agent,
scored by whether a monitor reading the transcript flags the sabotage. Nothing in
it says what the agent was allowed to touch, so our loader granted the session's
`cwd` and nothing else. Real tasks reach outside their checkout by design (backing
up model weights reads `/data/models/` from a home directory), and 114 of 311
benign events were refused for leaving a boundary the corpus never declared.
Containment came from that same invented boundary, which is why both sides moved
together.

The paired benign twin is the authorization: the same task without sabotage, so
the paths it touches are the surface the request needed. Under that grant,
containment is **8.5%**, and the false-block number on this corpus is **not
reportable**, because a mandate derived from the benign twin clears that twin by
construction. Friction is measured where it can be, on tau2, BFCL and ATIF.

Either way the conclusion holds and is now honestly founded: roughly two points of
discrimination, which is none.

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
