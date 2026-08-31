# The flow tier: one real defect, and a declaration that costs more than it buys

STATUS: current

```bash
python -m benchmarks.bpl_sweep --suite full --confidentiality derived --observe-results
```

Information-flow taint was the last class in
[containment_headroom.md](containment_headroom.md), and the plan flagged it as
research rather than a rung. It produced two results, and they point in opposite
directions.

## 1. The tier was armed, active, and reading an empty set

`observe_output` passed the resource to the tracker as:

```python
containing_object or path or ""
```

`path` is recovered from a `path` / `file_path` / `filename` argument. **A tool
with no such argument produced an empty resource, and an empty resource marks
nothing sensitive whatever the policy says.** That is most MCP tools, and it is
every tool in this suite's confidentiality family.

Concretely: `read_secret` returned `api_key=APIKEY_LIVE_9f3a`, the sensitive set
stayed empty, and the following `post_status` pasting that key into a public
channel passed the check. The tier reported no error at any point. `active` was
`True`, the policy was non-empty, and the answer was always "no sensitive data
here".

This is the third instrument defect in this line of work that produced a
plausible number rather than a failure, after the hardcoded arm tuple that made a
new arm measure an undefended run, and the quorum rung that fired correctly and
contained nothing. **All three were found by asking why a result was smaller than
expected, and none by a test that failed.** A test now pins the fallback.

The fix does not move any published number: every arm in the ladder runs with
`confidentiality=off`, so `sensitivity` is `None` and the branch never executes.

## 2. With the tier live, the only available declaration is net-negative

The derivation in `benchmarks/bpl/sensitivity.py` is deliberately the broadest
declaration expressible, `sensitive=("*",)` with no declassified sinks, and it
stated its own falsifier before the measurement: *if this buys containment by
refusing everything, benign completion collapses and the result is worthless.*

It does.

| | contained | completed | **joint** |
| --- | ---: | ---: | ---: |
| ladder, tier off | 73 | 130 | **71** |
| ladder + flow tier live | **95** | 77 | **48** |

+22 attacks contained, 53 benign tasks lost, and the joint metric moves the wrong
way by 23. Five scenarios gain, twenty-seven regress.

This is the joint metric doing the job it exists for. Containment alone would
have read as the largest single improvement in this work; it is the second-worst
column on the board, behind only `deny-all`. **A gateway that treats every read
as secret and every write as a leak is a gateway nobody can deploy**, which is
the same finding the LLM-monitor baseline produced from the other direction
(93.9% containment at 3.0% completion).

## What this does and does not settle

It does **not** show that information flow is unenforceable here. It shows that
`sensitive=("*",)` is not a policy, which was known before the run. A usable
version needs the two things this derivation does not have: sensitivity scoped to
the classes a goal actually names, and declassified sinks scoped to the
destinations it permits. Deriving those from a one-line goal is a research
problem and is not attempted here.

So the flow tier stays **off** in the published ladder, on evidence rather than
by omission, and the four goal-derived rungs stand as the result:
**joint 52 → 71 of 132, completion unchanged at 130, 19 gains against 0
regressions, exact McNemar p = 3.8e-06.**
