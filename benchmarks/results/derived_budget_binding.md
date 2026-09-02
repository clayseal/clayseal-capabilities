# The last manual field in a grant, derived

STATUS: current

```bash
python -m benchmarks.bpl_sweep --suite full --budgets derived+refuted
python -m benchmarks.bpl_sweep --suite full --budgets declared     # the baseline
python -m benchmarks.bpl_sweep --suite full --budgets none         # the deployment
```

## The gap this closes

Almost everything a grant needs is already derived: severity from the verb and
the resource ([monitor/consequence.py](../../clayseal/capabilities/monitor/consequence.py)),
sensitivity from a compiled taxonomy, ceilings from the organisation's own
delegation-of-authority document, the argument carrying an amount from the MCP
`tools/list` reply. One field was left manual on purpose, and
[policy_scaffold.py](../../clayseal/capabilities/policy_scaffold.py) said why:

> The catalog knows which argument carries the amount and the document knows what
> the ceilings are; which tool debits which ceiling is in neither, and it is the
> decision the whole aggregate rung rests on.

That field decides the largest single split in this benchmark. Where a grant
configures a budget the gateway contains 83.3% of attacks and where it does not,
18.9% ([bpl_suite_composition.md](bpl_suite_composition.md)). Across 520 tasks
from external corpora, **not one configures a budget**
([external_corpora_structure.md](external_corpora_structure.md)). So the field
nobody could generate is the field every real deployment is missing.

## The decision is smaller than the form makes it look

Writing `tracked` by hand reads as an N-tools-by-M-ceilings assignment. Across
every scenario in this suite that budgets value at all, **there is exactly one
ceiling: 34 of 34.** The operator is not choosing which limit a tool debits.
They are restating which of their tools spend, and the schema already says so in
the shape of an argument.

Multi-ceiling disambiguation is therefore implemented (a lexical tier that
abstains on a tie) and **untested on this suite**, because the suite contains no
case of it.

## Result

Full ladder arm, joint metric, n = 132.

| `budgets.tracked` | joint | contained | completed |
| --- | ---: | ---: | ---: |
| **none**, the state a grant arrives in | 43 | 45 | 130 |
| derived, conservative reading | 66 | 69 | 129 |
| derived, permissive reading | 69 | 73 | 128 |
| **derived + refuted by traffic** | **71** | **73** | **130** |
| derived + object identity + refuted | 72 | 75 | 128 |
| **declared**, written by the scenario author | **73** | **75** | **130** |

Deriving the field recovers **71 of the 73 scenarios a hand-written map contains,
at identical completion**, from a baseline of 43 with no budget configured. The
completion column is the point as much as the containment one: the derived map
refuses nothing the hand-written map permits.

The two it does not reach are `idempotent-double-pay` and
`retry-storm-double-effect`, and they fail for one reason, below.

## What the derivation reads

The ceilings and the tool schemas. Never the goal, never a trajectory, never a
tool result, never the scenario's label or its violation predicate. It runs once
per catalogue at compile time and writes a file a person reviews, the same
moment and the same trust tier as `policy_draft` and `compile_ontology`.

Monotone against the catalogue, because
[policy_scaffold.py](../../clayseal/capabilities/policy_scaffold.py) is right
that the thing describing the tools is the thing being constrained. A derived
binding may only ADD a debit. `merge_tracked` never overwrites one an operator
wrote. A server that renames its tools can cause more of its own calls to be
charged and can never cause fewer.

## Three findings worth keeping

**A phrase list loses, and the shape does not.** The first version read the
amount argument off a name list, and missed `fee`, `delta` and `tons`. Two of
those are ordinary names for an amount of money. Reading the argument's declared
JSON type instead, minus identifiers and paging controls, reaches all three, and
it is the same move `policy_draft` made when it stopped matching phrases for
money and started matching money.

A duration belongs on the exclusion list for a reason that took a measurement to
find: `advance_clock(hours=24)` is a number, is not a read, and debited 24
dollars against a money ceiling for moving the clock a day.

**Charge unless it is clearly a read, not only when it is clearly a spend.** The
conservative reading scores 66 and the permissive one 69. The difference is
exactly the tools an attacker would pick: `cashout_chips`, `file_claim`,
`force_replay` and `record_ops_adjustment` all carry a quantity, all move money,
and none says so in a word a list could hold. `record_ops_adjustment` is
described in its own catalogue entry as "looks like bookkeeping".

**Traffic refutes; it never proposes.** Replaying known-good traffic against the
derived map and dropping every binding that legitimate work contradicts is worth
+2 joint and removes every false block. This is the rule
[validate_ontology.py](../../benchmarks/validate_ontology.py) established for
compiled preconditions. It only ever removes a binding, because a grant inferred
from observed behaviour false blocks 42.99% of held-out work
([observed_grant.md](observed_grant.md)): what an agent has done is not evidence
of what it may do.

Two bugs in the first refutation pass are worth recording, because both dropped
the binding that was right:

- It summed a whole trace against a **rolling** ceiling.
  `rolling-window-hour-skew` legitimately pays 2,000 twice against a 3,000
  rolling limit with a day between them; read as a session total that is a
  breach, and the correct binding was dropped to explain it. Windowed budgets
  are now skipped, because saying nothing is the safe answer.
- Ties broke on the tool's name. In `round-trip-spend-wash` that dropped
  `pay_external` and kept `transfer` because `p` sorts before `t`. Ties now break
  on the smallest contribution to the overage, which is minimal repair: explain
  the breach by removing as little enforcement as accounts for it.

## The honest limit of the completion column

Refutation validates on the scenario's own benign twin, because that is the only
known-good trace a catalogue has here. So those runs **cannot** be refused
afterwards, and completion at 130 is guaranteed by construction rather than
measured. Containment is measured: refutation never saw the attack. This is the
same caveat [validate_ontology.py](../../benchmarks/validate_ontology.py) states
for the same reason. In deployment the validating traffic is historical and the
traffic being judged is new, so the guarantee is real but partial.

## What the schema cannot supply

`idempotent-double-pay` and `retry-storm-double-effect` are contained by a
declared map and not by a derived one, and the missing field is `identity_args`:
the arguments naming the object an effect lands on, which make it once-per-object
so one invoice cannot be paid twice through two calls each within the ceiling.

The declared answers are `(employee, period)` and `(key, vendor)`. Neither is
id-shaped, so the existing `_IDENTITY` pattern misses both. Taking every
non-quantity argument instead does reach them, and it recovers containment
exactly, 75 of 75, matching the hand-written map. It also makes every effect
once-per-object, which refuses the second legitimate payment to the same vendor:
completion falls from 130 to 125, and to 128 after refutation.

So identity is a genuine trade rather than a gap in effort. The default here is
off, and the reason is the joint metric: +2 contained against 2 benign tasks lost
is not an improvement in a system whose whole claim is that it does not add
friction.

## Three defects fixed on the way

1. **`extract()` never received the catalogue from either CLI path**, though
   `policy init --rules` had it in hand. `extract`'s docstring says the catalogue
   is what makes ordering and state-conditional rules extractable at all, so both
   classes were reaching the draft as TODO comments. Verified: an isolated
   `An order can only be cancelled if its status is 'pending'` now extracts one
   conditional rule where the CLI previously extracted none.
2. **`ToolFacts` read the tool description and discarded it.** It is the one
   place a server explains itself in the register the policy document was written
   in, which is what the lexical tier needs to bridge "invoices" to
   `make_payment`. `external_policy_documents_coverage.md` asserted `Catalog`
   already carried them; it did not.
3. **`SensitivityPolicy.content_markers` could not be read from a mandate.**
   `from_mandate` constructed three of four fields, so a mandate that declared
   the field was ignored in silence. The field stays empty by default, where
   [flow_content_classifier.md](flow_content_classifier.md) measured it.
