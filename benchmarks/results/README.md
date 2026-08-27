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
## Provenance

`python -m benchmarks.check_claims` is a CI gate. Every result file carries a
`STATUS:` line and the command that regenerates it, and the gate gives a
containment figure no standing without the cost beside it. `SEND_PACKET.md` is a
forbidden-claims list checked literally.
