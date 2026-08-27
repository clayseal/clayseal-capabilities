# What this system is measured on, and what the measurements say

STATUS: current

This is the map over the files in this directory. Every number below was
re-derived by running the command beside it, and each carries its cost, because
containment alone is won by refusing everything.

## The five headline results

| question | answer | reproduce |
| --- | --- | --- |
| Does it stop business-process attacks that per-call authorization cannot see? | **52 of 132 (39.4%)** attacks contained AND their benign twin completed, against 15 of 132 for dataflow taint | `python -m benchmarks.bpl_sweep --suite full` |
| Does it contain what leaves the goal's surface? | **100%** on every corpus: 189/189 agentharm, 7/7 sleight, 717/717 redcode, 2040/2040 asb, 1597/1597 injecagent | `python -m benchmarks.coverage --datasets agentharm,sleight,redcode,asb,injecagent,tau2,agentleak --limit 4000 --engines deployable-stack` |
| Does it contain what stays inside the surface? | **partly**: 196 of 507 agentharm (38.7%), 28 of 122 sleight (23.0%), 0 of 22 agentleak | same command, in-surface column |
| What does it refuse that it should not? | **0 of 20,619 benign events and 0 of 5,851 benign sessions**, eight corpora | `python -m benchmarks.session_units` |
| Do rules compiled from someone else's policy document break their own traffic? | **1 of 13,907** tau2 ground-truth actions blocked (0.007%) | `python -m benchmarks.tau2_policy_enforcement` |

## Read the two units, not one

Each flatters a different side, so both are published.

| corpus | per event | per session |
| --- | --- | --- |
| agentharm in-surface contained | 196/507 (38.7%) | **86/160 (53.8%)** |
| agentharm benign disrupted | 0/729 | 0/176 |
| sleight in-surface contained | 28/122 (23.0%) | **25/41 (61.0%)** |
| sleight benign disrupted | 0/311 | 0/43 |

Per-event containment understates protection, because a session stopped at its
first action scores 1 of 5 while the other four never happen. Per-event cost
understates disruption, for the mirror reason. A deployment sits between them.
`session_units.md`.

**A contained session still did part of what it set out to do.** On agentharm 97
attack actions ran before the first refusal, and the first stop lands on the
attack's opening action in 20 of 86 stopped sessions.

## Scope

**In-surface is where an authorization layer runs out.** Every residual
agentharm event is "within policy" at every rung, because the mandate itself
authorizes the harm: the grant for `agentharm-9-1` names hotel search and email
and its own task summary describes a drug handoff. That is a content-policy
question and this layer should not pretend to hold it.

**AgentLeak scores 0 of 22 and should.** Its ground truth calls
`read_patient(patient_id="PT-306502")` a leak because `patient_id` is outside
the allowed field set, so scoring 22 of 22 would mean refusing the task.
`agentleak_flow.md` works this through.

**Zero is not proof of zero.** At 5,851 benign sessions the 97.5% upper bound on
the disruption rate is about 0.06%. That is a bound, not an absence.

**The BPL suite is ours.** 132 scenarios written here, so it is not an
independent check of itself. It carries a selection audit
(`bpl_suite_composition.md`) showing the Core subset is worth 37 points on the
joint metric, which is why the full-suite number is the one quoted. The external
corpora (AgentHarm, sleight, RedCode, ASB, InjecAgent, tau2, AgentLeak, BFCL)
are the independent half.

## Policy, compiled from documents nobody here wrote

| | measure | reproduce |
| --- | --- | --- |
| rule-shaped sentences in four tau2 policy documents | 61 | `python -m benchmarks.policy_expressiveness` |
| enforceable by this library, written by hand | 47 of 61 (77%) | same |
| extracted and bound to a tool automatically | 10 of 61 (16%) | same |
| dropped silently | **0** | same |

`section_scope.md` is the most recent gain and `external_policy_documents_coverage.md`
reviews every automatic binding against the sentence it came from, because an
extracted rule naming the wrong tool is worse than a TODO: a TODO asks a
reviewer a question and a wrong binding answers it.
## What it costs

Performance numbers live in one place, [performance.md](performance.md), and
every other document links there. Before it existed, four files quoted four
different p50 latencies for "the full stack" — all correct for what they
measured, none of them saying which — and `baselines_audit.md` had flagged the
contradiction against us before anyone outside could.

| question | answer | reproduce |
| --- | --- | --- |
| What does one decision cost? | **34.1 µs** at the `Guardrail` boundary, 29,331/sec | `python -m benchmarks.gateway_cost` |
| Does it get slower as a session runs? | **No.** Cost at call 3,500 over cost at call 0 is a ratio of 1.0 over 4,000 calls | same command |
| What is the worst case? | **10.7 ms p99** in the confidentiality tracker, one run peaking at 219 ms. The open problem | `python -m benchmarks.flow` |
| What does it hold? | 11.7 KB per idle session, **1,182 bytes per decision, unbounded** | `python -m benchmarks.gateway_cost` |

## Provenance

`python -m benchmarks.check_claims` is a CI gate. It gives a containment figure
no standing without the cost beside it, and `SEND_PACKET.md` is a
forbidden-claims list checked literally.

### What is NOT reproducible from a command

This section used to say every result file carries a `STATUS:` line and the
command that regenerates it. That is not true, and the gate has been counting
the exceptions the whole time:

```
$ python -m benchmarks.check_claims
results files          105
stamped with STATUS     66
neither cmd nor status  23   baseline 23
bare zeros (total)     354   baseline 354
```

**23 of the 105 files carry numbers with neither a reproduction command nor a
status stamp.** They are working records of runs that happened, kept because
deleting a measurement because it is inconvenient to re-derive is worse than
publishing it with a caveat. But they are not evidence you can check, and they
should not be read as though they were. `why_we_fail.md` is the one to know
about, because THREAT_MODEL.md cites it for the 6.3% content-defined-harm
figure.

The **five headline results at the top of this file are not in that set.** Each
lists the command beside it, and those commands were re-run against this commit.

The `baseline` numbers are a ratchet: `check_claims` fails if either count goes
up, so the debt can shrink and cannot grow. That is the mechanism, and it is
weaker than "everything reproduces". Read the gate's output rather than this
paragraph if the two ever disagree again.

**354 bare zeros** are zeros printed without the upper bound that belongs beside
them. A zero over 12 trials and a zero over 132 are different evidence, and the
headline tables write both (`0/132, 97.5% upper bound 2.8%`). The 354 are in
files that do not.
