# Compile the ontology once per catalogue, enforce it deterministically

STATUS: current

```bash
python -m benchmarks.compile_ontology     # once per catalogue, offline
python -m benchmarks.precondition_rung    # deterministic, no model
```

Every general mechanism priced in [generalizing_derivation.md](generalizing_derivation.md)
needed structure somebody writes. Asking an operator for that **per prompt** is
not a product. But the structure is not per prompt: it is per **catalogue**. An
enterprise's tools change weekly; its prompts change constantly.

    compile time, once per catalogue   derive preconditions, effects and
                                       reversibility per tool. Reviewable,
                                       diffable, signable, versioned with the
                                       schema it describes.
    decision time, every call          deterministic checking against that
                                       artifact. No model, no network, no
                                       nondeterminism.

The compiler sees **the tool schema only**: name, description, parameters. Never
the goal, never a trajectory, never a violation predicate. This is asserted in
code (`_schema_only`), not promised. Using a model at compile time is not what
the provenance rule forbids; that rule governs what may widen authority at
decision time from attacker-influenceable input. A reviewed, signed artifact is
configuration, at the same trust tier as the schema it came from.

## What it buys with no goal text at all

An action whose declared preconditions are unmet is out of order, which is
precedence without parsing "A before B". An action declared irreversible is the
costly one, which is severity without a lexicon. Both are properties of the
catalogue.

Only facts some tool ESTABLISHES are enforced. A precondition over a fact nothing
produces describes the world before the session and is assumed to hold, since
otherwise the first action of every task is refused.

## Result

131 of 132 catalogues compiled. Alone, with no goal text:

| posture | contained | completed | joint |
| --- | ---: | ---: | ---: |
| step-up blocks | 31 | 114 | 20 |
| only severe denies | 28 | 117 | **21** |

**21 of 132 from the catalogue alone**, against 15 for dataflow taint, 7 for an
LLM monitor and 7 for a fitted plan distribution. Action-level lift is 1.43x
(4.9% of attack actions flagged against 3.4% of benign), better than the plan
distribution's 1.17x and still modest.

## Combined with the goal-derived rungs: a wash, and the reason is precise

| | contained | completed | joint | vs baseline |
| --- | ---: | ---: | ---: | --- |
| goal-derived stack | 75 | 130 | 73 | |
| + raw compiled ontology | 87 | 115 | 74 | +9 -8, p = 1.0 |
| + one review rule | 87 | 120 | 76 | +9 -6, p = 0.61 |

It **uniquely contains 9 scenarios**, including two this repository had documented
as underivable because their goals name no constraint:

```
toctou-stale-approval    fx-stale-ceiling-arb     checklist-interrupt-skip
kyc-expired-continue     capa-open-ship           mel-fly-expired
spoof-order-cancel       launder-then-alias-quorum  cover-then-heisenberg-pay
```

The catalogue names what those goals do not, which is the whole thesis of this
route and it is demonstrated.

It also costs 8 benign completions, and **every one is compiler
over-specification of the same kind**:

```
staged_count      requires delete_staged            a count, gated on the delete
whoami            requires persona_active           a read
approval_status   requires approval_token_minted    a read
trade_log         requires invoice_paid             a read
pay_vendor        requires open_payments_listed     workflow habit, not a requirement
```

Looking at what you are about to do is never gated on having done it. One review
rule, exempting observers, recovers 2 of the 8 and takes the arm to +9 -6. The
remaining six need `count` and `whoami` added to an observer lexicon, or a
reviewer's eye, and adding lexicon entries one at a time is the brittleness this
route existed to escape.

## What this establishes, and what it does not

**Established.** The split works: structure compiled once per catalogue,
enforcement deterministic and model-free per call, zero per-prompt human cost.
The artifact reaches cases no goal-derived rule can, because it reads the tools
instead of the sentence.

**Not established.** That an *unreviewed* compiled artifact is net-positive. At
+9 -8 it is a wash, and at +9 -6 after one automated review rule it is not
significant. The design assumed a person reviews the artifact once per catalogue;
this measures what that review is worth, and the answer is that it is not
optional. Every regression is an obvious error on inspection, which is the
argument that the review is cheap, and is not evidence that it can be skipped.

The honest headline is that a compiled ontology is a real and complementary
source of constraint whose accuracy, unreviewed, is not yet good enough to ship
alongside the lexical rungs.
