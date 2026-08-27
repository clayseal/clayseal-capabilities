# What this library can enforce, against what real policy says

STATUS: current

# Rule-shaped sentences, and how many survive the read

| document | lines | rule-shaped | extracted | of those, bound to a tool | dropped silently |
| --- | --: | --: | --: | --: | --: |
| airline | 167 | 29 | 5 | 5 | 0 |
| retail | 136 | 22 | 6 | 5 | 0 |
| telecom | 159 | 7 | 0 | 0 | 0 |
| mock | 7 | 3 | 0 | 0 | 0 |
| **total** | **469** | **61** | **11** | **10** | **0** |

## What shape are they

| shape | share | where it would be enforced |
| --- | --: | --- |
| ordering | 22/61 (36%) | tools.when `requires` (enforced, partly extracted) |
| state-conditional | 19/61 (31%) | tools.when `if`/`unless` (enforced, partly extracted) |
| other | 14/61 (23%) | not expressible by an authorization layer |
| numeric | 6/61 (10%) | value and call budgets (expressible, extracted) |

**47 of 61 (77%) are enforceable by this library once written into a policy by hand.** `tools.when` covers both large classes: `if`/`unless` for a state condition, `requires` for an ordering rule, both as monotone withdrawals from `tools.allow`.

**10 of 61 (16%) are extracted and bound to a tool automatically**, against 1 before. The remainder still arrive as TODO comments for a person, and the reason is worth naming because the reason named here previously was WRONG. It was not line wrapping. A rule sits under a HEADING that names its operation once and never names it again in the sentence itself, and the reader skipped headings outright; reading the section a sentence sits in took tau2's airline document from 0 enforceable rules to 4. What is left is a vocabulary gap rather than a reading one: the telecom document argues about bills, lookup and suspension while its tools are named `make_payment`, `refuel_data` and `resume_line`, and no reader working from tool NAMES can bridge that. Tool DESCRIPTIONS can, and `policy_scaffold.Catalog` already carries them. See `benchmarks/results/section_scope.md`.

Nothing rule-shaped was dropped silently: 11 extracted and 59 flagged for a reviewer, over 61 rule-shaped sentences.

## Where this stands now

Four passes, on the same four documents nobody here wrote.

| | enforceable by hand | extracted and bound automatically |
| --- | --: | --: |
| before any of this | 28 of 61 (46%) | 1 of 61 |
| after `tools.when if/unless` | 47 of 61 (77%) | 1 of 61 |
| after `requires` and the catalogue-bound reader | 47 of 61 (77%) | **7 of 61** |
| after the section-scope reader | 47 of 61 (77%) | **10 of 61** |

`tools.when` covers both large classes as monotone withdrawals from
`tools.allow`: `if`/`unless` for a state condition, `requires` for an ordering
rule. A guard may only ever remove a tool, and the compiler refuses an admitting
form, because facts arrive from tool output and an `admit-when` rule would let
an injected `status: pending` widen a grant.

Ordering reads a fact the GATEWAY sets about its own ALLOW decisions rather than
anything a tool returned, and `observe_facts` refuses to write one. Without that
refusal an injected `{"called:list_orders": true}` would satisfy a precondition
nobody met.

## What a refusal looks like now

The citation travels from the document into the runtime, so an operator reading
a denial sees the sentence rather than a fact dictionary:

```
cancel_order  deny  tool 'cancel_order' withdrawn:
                    line 16: Before taking any action that updates the database
                    (cancel, modify, return, exchange), you must list the order first
```

## What the extraction costs: every binding, reviewed

An extracted rule that names the wrong tool is worse than one left as a TODO,
because a TODO asks a reviewer a question and a wrong binding answers it. All
ten were checked against the sentence they came from, one at a time, against
tau2's real tool catalogue.

| document | rule | binds | correct? |
| --- | --- | --- | --- |
| retail 16 | list before any updating action | requires `list_orders`, denies the five updating tools | yes |
| retail 88 | cancel only while pending | unless `status: pending`, denies `cancel_order` | yes |
| retail 96 | modify only while pending | unless `status: pending`, denies `modify_order`, `modify_address`, `modify_payment` | yes, and the three `modify_*` tools are what the sentence means |
| retail 118 | return only when delivered | unless `status: delivered`, denies `return_order` | yes |
| retail 130 | exchange only when delivered | unless `status: delivered`, denies `exchange_order` | yes |
| airline 7 | list before any booking change | requires `list_reservations`, denies `book_reservation`, `update_reservation` | yes |
| airline 116 | no cabin change once flown | if `flight_in_the_reservation: flown`, denies `change_cabin` | binding correct, **fact name is a guess** |
| airline 65 | get the user before booking | requires `get_user`, denies `book_reservation` | yes, **inferred** from `## Book flight` |
| airline 105 | get user and reservation before modifying | requires `get_user`, `get_reservation`, denies `update_reservation`, `change_cabin` | yes, **inferred** from `## Modify flight` |
| airline 135 | get user and reservation before cancelling | requires `get_user`, `get_reservation`, denies `cancel_reservation` | yes, **inferred** from `## Cancel flight` |

**Ten of ten bind to the right tools. One carries a fact name nobody can
confirm from the document.** `flight_in_the_reservation` is what the sentence
reads as, and whether the tool returns a field by that name is a fact about the
server rather than the policy. The draft says so at the line: every conditional
carries `# CHECK the fact name against what the tool actually returns`, and an
unconfirmed precondition WITHDRAWS, so a wrong fact name refuses the tool rather
than admitting it. The error direction is the safe one and it is still an error.

The ordering rules carry no such risk. Their facts are set by the gateway on its
own ALLOW decisions, so there is no server field to guess at.

## Why the other 51 still need a person

Named rather than rounded away.

**The document and the tool catalogue use different words.** This is what is
actually left. tau2's telecom policy argues about bills, lookup and suspension
while its tools are named `make_payment`, `refuel_data` and `resume_line`. No
reader working from tool NAMES can bridge that, however it reads the document.
Tool DESCRIPTIONS can, and `policy_scaffold.Catalog` already carries them.

**A rule whose subject is a business noun has nothing to match.** "Basic economy
flights cannot be modified" is about a fare class, not a tool, and the catalogue
holds tool names. Binding it needs a mapping from business object to tool that
no document carries.

**23% are not expressible by an authorization layer at any level.** "Transfer
the user to a human agent if the request is out of scope" is not a rule about
authority, and this layer should not pretend to hold it.
