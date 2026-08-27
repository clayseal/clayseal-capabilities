# Section-scoped policy extraction

STATUS: current

```bash
python -m benchmarks.policy_expressiveness
python -m benchmarks.tau2_policy_enforcement
```

Operational policy names an operation once, in a heading, and states the rules
for it as bullets that never name it again:

```
## Cancel flight

First, the agent must obtain the user id and reservation id.
- The user must provide their user id.
```

`extract` now reads that structure, so a rule inherits the tool scope of the
section it sits in.

## The mechanism

**A heading must name an act, not a thing.** Tool names are verb-then-noun, so
the test is a match on the leading word. `### Order` and `### User` open data
dictionaries, and their bullets define attributes rather than state rules.

**A heading replaces its own level and clears everything deeper**, including
when it names no operation, so a section that names nothing does not inherit the
scope of the section before it.

**A subsection narrows its parent.** `### Modify items` alone admits all three
`modify_*` tools; inside `## Modify pending order` it is `modify_order`.

**A tie is kept when the tied tools matched the same word.** `## Modify flight`
over a catalogue holding `update_reservation` and `change_cabin` is one section
covering two tools. A tie across different words abstains, leaving the sentence
as a TODO for a reviewer.

**A prerequisite is resolved by verb first, phrase second.** The rule's verb
picks the candidates and the rest of the phrase chooses between them.
Parentheticals are stripped: they elaborate, and never name the object of the
verb.

**A section binding is marked `inferred` and carries its heading in the
citation**, so a reviewer sees the inference and can disagree with it.

## Result

| | before | after |
| --- | --: | --: |
| external rules bound automatically | 7 of 61 (11%) | **10 of 61 (16%)** |
| airline rules compiled, tau2's own catalogue | 0 | **4** |
| tau2 ground-truth actions falsely blocked | 1 of 13,907 | **1 of 13,907** |

A 167-line policy document that yielded nothing now yields four rules, each
reviewed against the sentence it came from and against tau2's real tool
catalogue, at no cost to the 13,907 actions tau2 ships as ground truth.

Containment on tau2's refusal tasks is unchanged: on those tasks the agent
already calls `get_user_details` before it writes, so a precondition requiring
it has nothing to stop. The claim is coverage at no cost.

## What is left

Telecom yields nothing, and the limit is vocabulary rather than structure. Its
policy argues about bills, lookup and suspension; its tools are named
`make_payment`, `refuel_data`, `resume_line`, `toggle_roaming`. No reader working
from tool NAMES can bridge that. Tool DESCRIPTIONS can, and
`policy_scaffold.Catalog` already carries them. That is a different mechanism and
belongs in its own measurement.

A light verb carries no act and the noun after it does, so `make_payment` is a
payment tool. The scope resolves for `## Overdue Bill Payment`, and nothing
downstream consumes it yet: the sentences under that heading state neither an
ordering nor a state condition.
