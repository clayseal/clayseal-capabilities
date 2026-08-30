# Attack-class coverage: what an authorization layer can and cannot decide

STATUS: current

```bash
python -m benchmarks.coverage --datasets agentharm,sleight,redcode,asb,injecagent,tau2,agentleak --limit 4000 --engines deployable-stack
```

Re-derived against this commit. The previous revision was stamped `unverified`
and had drifted: it counted 652 AgentHarm attack events where the loader now
yields 696, and its per-corpus tables were still the six-rung ladder rather than
the shippable stack.

tau2 carries no attack events, so it produces no containment row. It is named in
the command because the partition is worth running over it, and the absence is
the answer.

Attacks are partitioned without consulting any engine. `surface-leaving` means at least one field (tool, resource, action, target) falls outside what the task's own mandate and benign trajectory establish. `in-surface` means every field is one the task legitimately uses, so a per-call authorization layer has nothing to object to.

## Class mix per corpus

| Corpus | attack events | surface-leaving | in-surface |
| --- | --: | --: | --: |
| agentharm | 696 | 189 / 696 | 507 / 696 |
| sleight | 129 | 7 / 129 | 122 / 129 |
| redcode | 718 | 717 / 718 | 1 / 718 |
| asb | 2040 | 2040 / 2040 | 0 / 2040 |
| injecagent | 1598 | 1597 / 1598 | 1 / 1598 |
| agentleak | 22 | 0 / 22 | 22 / 22 |

## agentharm: containment by class

| Engine | surface-leaving | in-surface |
| --- | --- | --- |
| deployable-stack | 100.0% [97.0%, 100.0%] | 38.7% [32.8%, 44.2%] |

Fields that left the surface: resource (189), tool (41), action (10)

## sleight: containment by class

| Engine | surface-leaving | in-surface |
| --- | --- | --- |
| deployable-stack | 100.0% [25.0%, 100.0%] | 23.8% [16.6%, 31.7%] |

Fields that left the surface: target (7)

## redcode: containment by class

| Engine | surface-leaving | in-surface |
| --- | --- | --- |
| deployable-stack | 100.0% [99.6%, 100.0%] | 0.0% [0.0%, 79.3%] |

Fields that left the surface: target (717)

## asb: containment by class

| Engine | surface-leaving | in-surface |
| --- | --- | --- |
| deployable-stack | 100.0% [94.1%, 100.0%] | n/a |

Fields that left the surface: tool (2040), resource (2040), action (40)

## injecagent: containment by class

| Engine | surface-leaving | in-surface |
| --- | --- | --- |
| deployable-stack | 100.0% [99.7%, 100.0%] | 0.0% [0.0%, 79.3%] |

Fields that left the surface: tool (1597), resource (1597), action (1086)

## agentleak: containment by class

| Engine | surface-leaving | in-surface |
| --- | --- | --- |
| deployable-stack | n/a | 0.0% [0.0%, 13.6%] |

## Reading

A headline containment number is a weighted average over this mix, and every corpus here picks its own weights. Quoting one number across corpora with different mixes compares nothing. The defensible claim is per class: authorization contains what leaves the surface, and does not decide what stays inside it. The in-surface column is where aggregate limits (budgets, rates) and the behavioral layer have to do the work, and where an honest evaluation should concentrate rather than adding more surface-leaving corpora.
