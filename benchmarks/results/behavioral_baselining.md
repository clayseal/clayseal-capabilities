# Behavioural baselining from existing traffic: measured, and it converges to nothing

STATUS: current, with one conclusion CORRECTED. This file previously ended by
claiming this class cannot be learned from behaviour. That was too strong for the
evidence: the three methods tested here are all UNCONDITIONED, and conditioning
on the task is a different idea, tested separately in
[plan_sets.md](plan_sets.md). The correct statement is narrower and appears at
the end of this file.

```bash
python -m benchmarks.mined_precedence
python -m benchmarks.plan_distribution
```

The ideal gateway needs nothing on day one and hardens itself from activity the
deployment already produces. No goal that names its constraint, no declared
ontology, no compile step, no review. This is the specification-mining idea, and
it is mature: Perracotta (Yang et al., ICSE 2006) mines temporal API rules from
IMPERFECT traces using a satisfaction ratio instead of demanding every trace obey
every rule.

Applied here, the pattern is the simplest one: **"A precedes B"**, kept when B
occurs often enough and A came first often enough. No model, no schema, no human.

It was built and it does not work on this class. The reason generalises past this
implementation.

## The naive number, and why it is memorisation

Mined from one benign trace per catalogue and combined with the goal-derived
rungs, the arm scores **joint 85, +12 -0, p = 0.0005**, beating the compiled
ontology's 83.

That number is worthless, and one test says so. Swap two READ-class actions in a
benign trace, a variation any real session may produce, and the mined rules
refuse **29% of them**. With one trace, every tool that happened to precede B
becomes a required predecessor of B: confidence is 1.0 by construction and the
miner memorises the transcript. This is `observed_grant.md`'s 42.99% held-out
false-block, one level up.

## The learning curve

Perracotta assumes many traces so that confidence separates a rule from a
coincidence. Simulating that, with sessions that do the same work and order their
reads differently:

| sessions per catalogue | rules kept | contained | joint | unseen benign variant refused |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 945 | 103 | 34 | 73% |
| 3 | 446 | 89 | 59 | 36% |
| 5 | 295 | 82 | 72 | 19% |
| 10 | 164 | 77 | 74 | 4% |
| 25 | 97 | 76 | 73 | 1% |

The miner behaves exactly as the technique predicts. Spurious rules wash out,
945 falling to 97, and the false-block rate on unseen legitimate variation
collapses from 73% to 1%.

**And the joint score converges to 73, which is the baseline without it.** Every
gain visible at low session counts was memorisation. At the operating points
where the arm is safe to deploy, it adds nothing.

## Why, and this is the general result

Two independent methods now converge on the same answer. A fitted Markov model
over action sequences flags attack actions at 1.17x the benign rate
([plan_distribution.md](plan_distribution.md)). Mined precedence, once its false
blocks are tolerable, adds +1 and then +0.

**Correct behaviour does not demonstrate the rule. It merely never violates it.**

That holds for a model of behaviour in general, fitted on pooled traffic with no
view of the task. It does not settle what a TASK-CONDITIONED model can do, which
is a separate question with a separate answer in [plan_sets.md](plan_sets.md):
such a model is a real signal on the 23% of attacks that deviate from the stated
task, and is structurally blind to the 77% where the task itself is what breaches
the policy.

A thousand sessions in which nobody split a payment to evade a ceiling contain no
evidence that splitting is forbidden; they contain payments. The constraint lives
in the policy, not in the trace, and a model of what usually happens cannot
recover a rule that usual behaviour never has occasion to exercise. This is the
same reason the attack sequences are not anomalies: they are made of ordinary
actions in ordinary order.

## What this says about the design

It settles where structure has to come from, and it is not from traffic.

The compiled ontology succeeds where mining fails, at +10 and p = 0.002
([validated_ontology.md](validated_ontology.md)), and the difference is what each
one reads. A tool schema declares **semantics**: this action requires that fact,
this effect cannot be undone. Traffic shows **habit**: this usually happens before
that. Semantics carries the constraint; habit does not.

Traffic still has one job, and it is the job it is good at. It cannot supply the
rules, and it can **refute** them: a precondition that legitimate traffic violates
is not a precondition, which is what takes the compiled artifact from a wash to
+10 with no human review. Mining for rules fails; mining for counterexamples
works.
