# The compiler, tested on policy documents nobody here wrote

STATUS: current

```bash
python -m benchmarks.policy_expressiveness --domains airline,retail,telecom,mock
```

`policy_draft.py` turns a written business rule into a policy draft, and its
central safety claim is stated in its own docstring: **nothing rule-shaped is
dropped silently**, because a rule that vanished in translation is worse than
one that was never attempted, the reviewer having no way to notice.

That claim was true of the delegation-of-authority document it was built
against. This is what happened on four policy documents from `tau2-bench`,
469 lines of prose authored elsewhere.

The rule-shaped detector in `policy_expressiveness.py` is deliberately
independent of the extractor's own marker list. Measuring the extractor against
its own markers would report perfect coverage by construction; the two readings
are separate, and their disagreement is the finding.

## The invariant failed on external prose

| markers | rule-shaped | extracted | flagged TODO | **dropped silently** |
| --- | --: | --: | --: | --: |
| as first written | 61 | 1 | 9 | **51 of 61** |
| after this pass | 61 | 1 | 69 | **0 of 61** |

One rule read out of sixty-one, and fifty-one sentences that state a constraint
produced no output at all, not even the TODO the module promises. Both rows are
the same documents under the same measurement, so the difference is the marker
set and nothing else.

The cause is that `RULE_MARKERS` was a list of the phrases the *first* document
happened to use. It is a held-out generalization failure of our own tooling,
found the only way it could be: by running it on data nobody here authored.

## What real policy actually says

Classifying the 61 by shape explains the miss and is the more useful half:

| shape | share | example | expressible here? |
| --- | --: | --- | --- |
| ordering / positive obligation | 22/61 (36%) | "The agent must first obtain the user id and reservation id" | yes, as a required predecessor phase, and the extractor emits none |
| state-conditional | 19/61 (31%) | "Cabin cannot be changed if any flight has already been flown" | partly: guards tighten ceilings, not tool admissibility |
| not expressible | 14/61 (23%) | "Transfer the user to a human agent if the request is out of scope" | no, and an authorization layer should not pretend otherwise |
| numeric limit | 6/61 (10%) | "Each reservation can have at most five passengers" | yes, and this is the shape the extractor was built for |

**The machinery is built for the 6 of 61.** `external_corpora_structure.md`
concluded that organisations write their ceilings down. These documents say they
mostly write down an ORDER of operations and a set of state preconditions, and
the numeric ceiling is the rare case at 10%.

Two thirds of what they do say is expressible here. Ordering is a required
predecessor phase, which the intent envelope has enforced from the start and the
extractor emits none of. State conditions are two thirds of the way to
`budgets.value.when`, which already carries fact-conditioned guards.

## After the fix

`RULE_MARKERS` now carries the forms these documents use, including the positive
obligations that a prohibition-only reading could never see.

Sixty-nine TODOs on 469 lines is a lot to hand a person, and it is the correct
amount: the alternative was fifty-one constraints that nobody would ever learn
had been missed. The marker set widens the TODO net rather than the rule net,
which is the safe direction, and the delegation-of-authority round trip is
unchanged.

## Friction on external policy-following traffic

The same corpora, run through the shipped stack, measuring only what it does to
legitimate work. This is the cost column on data authored elsewhere.

| corpus | tasks | benign events | interrupted |
| --- | --: | --: | --: |
| tau2 | 1200 | 5441 | **1 of 5441 (0.02%)** |
| bfcl | 1200 | 1200 | **0 of 1200, upper bound 0.3%** |

One interruption in 6,641 benign events, and it is a step-up rather than a
refusal: `book_reservation occurrence 2 of a phase the sealed goal accounts for
once`, which is the derived-count rung doing exactly what it is for.

That number is worth holding next to the 6.3% and 14.1% benign cost on
`agentharm` and `sleight`. Those corpora are adversarially framed and their
benign traffic sits inside attack scenarios. On clean external agentic traffic
the floor is close to transparent.

## What this changes

**The honest external claim is two-sided.** The enforcement floor imposes almost
no friction on 6,641 benign events from corpora nobody here wrote. The document
compiler, on prose nobody here wrote, reads one rule in sixty-one and now at
least admits to the other sixty.

**The next two mechanisms are named by the data rather than by us**, in the
order the data ranks them.

*Ordering, 36%.* The envelope enforces required predecessor phases already and
`policy_draft` emits no phases at all. This is the largest single class and the
gap is in the compiler rather than in the enforcement.

*State conditions, 31%.* `budgets.value.when` carries fact-conditioned guards
that may only tighten. The missing piece is letting a guard remove a TOOL rather
than only lower a ceiling, which is a small extension of a mechanism that exists
and keeps its monotone property.

Neither is claimed here. What is claimed is that the ranking came from 469 lines
of somebody else's policy rather than from our sense of what to build next.
