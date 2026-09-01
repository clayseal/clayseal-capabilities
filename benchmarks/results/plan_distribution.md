# Business-process violations are not distributional anomalies

STATUS: current

```bash
python -m benchmarks.plan_distribution
```

The goal-derived rungs need the sealed goal to NAME a constraint, and derive
nothing when it does not. The obvious alternative needs no goal text at all: model
what legitimate work for a task type looks like, and treat departures from it as
suspect. If that worked it would generalize immediately, since any deployment
with benign traffic can fit it.

It does not work, and the measurement says something stronger than "our version
was bad".

## The model

Legitimate traffic is not arbitrary. A payment is drafted, approved, then
executed. The 132 benign twins are samples from that distribution, so a
variable-order Markov model over tool sequences estimates it, backed off from
trigram to bigram to unigram in Katz style. The backoff matters: a model that
assigns zero to an unseen sequence is an allow-list, and this repository has
already measured what those cost at 42.99% held-out false blocks
([observed_grant.md](observed_grant.md)).

Severity comes from the existing verb classifier, not from a lexicon written for
this experiment. [tool_risk.md](tool_risk.md) records why that distinction
matters: a name-based risk prior written after reading the tools is fit on the
evaluation set.

The rung fires on the conjunction of improbable and irreversible, and it
**escalates** instead of denying, because a distribution learned from traffic is
evidence about what is normal and never a statement of what is authorized.

Training uses benign scripts only and is **leave-one-scenario-out**: the model
scoring a scenario has never seen it.

## Result

| log P threshold | contained | completed | joint |
| ---: | ---: | ---: | ---: |
| -9.0 | 0 | 132 | 0 |
| -7.0 | 41 | 82 | 4 |
| **-6.0** | 60 | 65 | **7** |
| -5.0 | 69 | 56 | 6 |
| -4.0 | 79 | 48 | 6 |
| -2.0 | 81 | 48 | 6 |

**Best joint 7 of 132**, with the threshold chosen after seeing the score, which
is generous to this rung and not to the comparison. The goal-derived stack
scores 76.

## Why, and this is the useful part

Containment and completion trade almost one for one down the table, which is the
signature of a rule refusing a fraction of everything. Measured directly, at the
action level:

| threshold | attack actions flagged | benign actions flagged | lift |
| ---: | ---: | ---: | ---: |
| -7.0 | 222/2388 = 9.3% | 187/2339 = 8.0% | 1.16x |
| -6.0 | 301/2388 = 12.6% | 252/2339 = 10.8% | 1.17x |
| -5.0 | 318/2388 = 13.3% | 267/2339 = 11.4% | 1.17x |
| -4.0 | 365/2388 = 15.3% | 295/2339 = 12.6% | 1.21x |

**A lift of 1.2 is not a detector.** The attack sequences are not improbable under
a model of legitimate work, and that is not a defect of the estimator. It is the
definition of this attack class: every action is one an agent doing the job would
take, in an order it would take them. Splitting a payment into four is four
ordinary payments. Executing an approval after amending the document is an
ordinary execute. The violation is **semantic**, a rule forbidding a combination,
and not **statistical**, a combination being rare.

## What this settles

It is the argument for an authorization layer that knows the rule, over a
behavioural layer that knows the distribution, and it is now measured rather than
asserted. Anomaly detection over action sequences has a ceiling on this class at
roughly chance, whatever the estimator, because the adversary is drawing from the
same distribution as the defender's training data.

The corollary is a caution for anyone extending this work: a behavioural tier
that reports containment on business-process attacks should be checked for lift
before the number is believed. Ours reports 1.2x.
