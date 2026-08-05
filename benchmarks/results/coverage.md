# Attack-class coverage: what an authorization layer can and cannot decide

Attacks are partitioned without consulting any engine. `surface-leaving` means at least one field (tool, resource, action, target) falls outside what the task's own mandate and benign trajectory establish. `in-surface` means every field is one the task legitimately uses, so a per-call authorization layer has nothing to object to.

## Class mix per corpus

| Corpus | attack events | surface-leaving | in-surface |
| --- | --: | --: | --: |
| redcode | 718 | 717 (100%) | 1 (0%) |
| agentharm | 652 | 41 (6%) | 611 (94%) |
| asb | 2040 | 2040 (100%) | 0 (0%) |

## redcode: containment by class

| Engine | surface-leaving | in-surface |
| --- | --- | --- |
| allow-all | 0.0% [0.0%, 0.8%] | 0.0% [0.0%, 79.3%] |
| tool-allowlist | 0.0% [0.0%, 0.8%] | 0.0% [0.0%, 79.3%] |
| capability-token | 0.0% [0.0%, 0.8%] | 0.0% [0.0%, 79.3%] |
| task-scope | 100.0% [99.2%, 100.0%] | 0.0% [0.0%, 79.3%] |
| task-scope+binding | 100.0% [99.2%, 100.0%] | 0.0% [0.0%, 79.3%] |
| task-scope+binding+budget | 100.0% [99.2%, 100.0%] | 0.0% [0.0%, 79.3%] |

Fields that left the surface: target (717)

## agentharm: containment by class

| Engine | surface-leaving | in-surface |
| --- | --- | --- |
| allow-all | 0.0% [0.0%, 9.1%] | 0.0% [0.0%, 1.7%] |
| tool-allowlist | 100.0% [90.9%, 100.0%] | 0.0% [0.0%, 1.7%] |
| capability-token | 100.0% [90.9%, 100.0%] | 0.0% [0.0%, 1.7%] |
| task-scope | 100.0% [90.9%, 100.0%] | 0.0% [0.0%, 1.7%] |
| task-scope+binding | 100.0% [90.9%, 100.0%] | 0.0% [0.0%, 1.7%] |
| task-scope+binding+budget | 100.0% [90.9%, 100.0%] | 0.0% [0.0%, 1.7%] |

Fields that left the surface: tool (41), resource (41), action (10)

## asb: containment by class

| Engine | surface-leaving | in-surface |
| --- | --- | --- |
| allow-all | 0.0% [0.0%, 5.9%] | n/a |
| tool-allowlist | 100.0% [94.1%, 100.0%] | n/a |
| capability-token | 100.0% [94.1%, 100.0%] | n/a |
| task-scope | 100.0% [94.1%, 100.0%] | n/a |
| task-scope+binding | 100.0% [94.1%, 100.0%] | n/a |
| task-scope+binding+budget | 100.0% [94.1%, 100.0%] | n/a |

Fields that left the surface: tool (2040), resource (2040), action (40)

## Reading

A headline containment number is a weighted average over this mix, and every corpus here picks its own weights. Quoting one number across corpora with different mixes compares nothing. The defensible claim is per class: authorization contains what leaves the surface, and does not decide what stays inside it. The in-surface column is where aggregate limits (budgets, rates) and the behavioral layer have to do the work, and where an honest evaluation should concentrate rather than adding more surface-leaving corpora.
