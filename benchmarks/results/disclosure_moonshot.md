# Reads are disclosures

STATUS: current

```bash
python -m benchmarks.session_units --datasets agentharm,sleight
python -m benchmarks.coverage --datasets agentharm,sleight,redcode,asb,injecagent,tau2,agentleak --limit 4000 --engines deployable-stack
```

A read puts content into a context that every later action can act on, and no
later action can remove it. The agent that read the customer table has the
customer table, whether or not its next call is refused. Of AgentHarm's 507
in-surface attack events, 275 are reads and calls.

## The mechanism

`ConsequenceLevel` carries `DISCLOSURE = 1` beneath `WRITE = 2`, and a read that
names a target classifies into it. Every existing comparison against `WRITE` is
unchanged by construction, so no rung that asks for a mutation sees reads.

The predicate is split, and the split is what carries the result:

| predicate | means | used by |
| --- | --- | --- |
| `is_consequential` | DISCLOSURE or above | detection, escalation, replan gating |
| `is_effectful` | WRITE or above | every rung that ends in an unrecoverable DENY |

A disclosure escalates and never refuses. An envelope with imperfect recall will
miss legitimate reads, and a step-up lets a supervisor wave those through, where
a denial the supervisor cannot lift turns every recall miss into lost work.

## Containment

| corpus | unit | before | after |
| --- | --- | --: | --: |
| agentharm | per event, in-surface | 152 of 507 (31.6%) | **196 of 507 (38.7%)** |
| agentharm | per session | 45.0% | **53.8%** |
| sleight | per event, in-surface | 28 of 122 (23.0%) | 28 of 122 (23.0%) |
| sleight | per session | 61.0% | 61.0% |

Surface-leaving containment is unchanged at 100% on every corpus: 189 of 189
agentharm, 7 of 7 sleight, 717 of 717 redcode, 2040 of 2040 asb, 1597 of 1597
injecagent. This rung was never the one deciding those.

Attacks are also stopped **earlier**. Actions that ran before the first refusal
fell from 113 to 97 while more sessions were stopped, and the first stop landing
on the attack's opening action went from 4 of 74 sessions to **20 of 86**.

## Cost

| corpus | benign events refused | benign sessions disrupted |
| --- | --: | --: |
| agentharm | 0 of 729 | 0 of 176 |
| sleight | 0 of 311 | 0 of 43 |
| redcode | 0 of 344 | 0 of 50 |
| asb | 0 of 102 | 0 of 51 |
| injecagent | 0 of 1054 | 0 of 1054 |
| tau2 | 0 of 14842 | 0 of 2545 |
| agentleak | 0 of 5 | 0 of 5 |
| bfcl | 0 of 3232 | 0 of 1927 |
| **total** | **0 of 20,619** | **0 of 5,851** |

The reason it is free is structural: a benign read is an on-plan read, so the
reclassification fires only on a read the sealed goal did not ask for. It
changes what happens to actions already outside the envelope and does not move
the envelope's boundary. At 5,851 benign sessions the 97.5% upper bound on the
disruption rate is 0.06%.

## Scope

AgentLeak stays at 0 of 22. Its attacks are a single authorized action that is
itself the harm, so there is no departure for a consequence classifier to grade.
