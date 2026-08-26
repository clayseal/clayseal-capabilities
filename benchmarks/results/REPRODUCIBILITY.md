# Which results can be checked, and which cannot

STATUS: current

```bash
python -m benchmarks.verify_results
python -m benchmarks.check_claims
```

A results file is a claim about what the code does. This tracks whether anyone
can check it.

## Where it stands

| | count |
| --- | ---: |
| results files | 80 |
| carry a `STATUS:` header | 40 |
| say what produced them | 52 |
| declare a command this gate can run | 26 |
| **neither a command nor a status** | **24** |

Both counts are ratcheted in `check_claims` and baselined in
`.claims_baseline.json`. Adding a results file with neither fails the check. That
is the part that is finished: the debt is bounded and cannot grow.

## Why the 24 are not just fixed outright

The obvious approach is to guess each one's command until the numbers match. It
was tried on thirteen and abandoned, because it is not verification. Running
`python -m benchmarks.drift` against `drift.md` compares two different
experiments: the file reports 2,000 actions and the module defaults to 10,000.
Adding `--actions 2000` made it reproduce, which is a fix. Trying flags until a
number matches is fitting, and a verifier that does it certifies whatever it was
pointed at.

So the honest state is that these results were produced with parameters nobody
wrote down, and recovering those parameters needs the person who ran them, not a
search.

## The queue

Grouped by what each would need. Nothing here blocks a release; it blocks
someone else checking our arithmetic, which is a different and slower problem.

**Deterministic, needs its parameters recovered (11).** These run without a model
or a key, so once the command and its flags are written into the file,
`verify_results` checks them on every run.

`bpl_aggregate`, `commit_then_reveal`, `coverage`, `detector`, `full_stack_benchmark`,
`latency_redcode`, `rigor_pass`, `scoreboard`, `sleight_detector`, `trajectory`,
`why_we_fail`

**Needs a model and a key (7).** Not verifiable in a gate at all. These need a
`STATUS:` decided by a person, and the model identity recorded per
`core/reporting.ModelIdentity`.

`agentdojo_first_run`, `agentharm_content`, `frontier_workspace`, `head_to_head`,
`hint_retry`, `live_agentdojo`, `provenance`

**Long-running adversarial search (4).** Reproducible but not in a fast gate;
`adaptive_stack_labelfree.md` is the worked example of how one of these should
look, with its command, its seed and its candidate count in the header.

`adaptive_adversary`, `adaptive_destruction`, `adaptive_exfiltration`,
`adaptive_persistence`

**Other (2).** `baselines_sourced` is a citation list rather than a measurement.
`held_out_generalization` predates the harness that would reproduce it.

## What a results file needs

Two things, and the second is the one that gets forgotten:

````markdown
# What this measures

STATUS: current

```bash
python -m benchmarks.drift --actions 2000
```
````

The command **with its parameters**. A bare module name is worse than nothing: it
looks like a reproduction instruction and silently runs a different experiment.

## The verifier is advisory, on purpose

`verify_results` compares the figures in a file against the figures a rerun
prints. It has a false-positive class it cannot cheaply fix: a table cell may
hold a historical value, and `commit_totality.md` reporting
`NEVER_RAISES | 0 *(was 46)*` is correctly missing 46 from a current run.

So only an `ok` is evidence, and it is not wired into CI. Four bugs in it were
found while writing it, which is the same argument in another form: comparison
direction reversed, dates in prose read as figures, thousands separators split
into two numbers, and shell paths matched as Python module names.
