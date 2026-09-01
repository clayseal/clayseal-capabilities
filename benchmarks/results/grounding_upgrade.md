# Can the goal-to-tool grounding be made general? Three attempts, measured

STATUS: current

The five goal-derived rungs parse a clause from the sealed goal and ground each
side against the tool catalogue by token overlap. That is regex, and it does not
generalise: `"SoD: separate preparer and approver"` cannot reach
`draft_payment`, because "preparer" and "draft" share no token. This records
three attempts to replace it, the evidence for each, and why none shipped.

## 1. Sentence embeddings for grounding. REFUTED.

The obvious upgrade: embed the role phrase and each tool's description, ground by
cosine similarity. This satisfies the provenance rule, since a tool schema is
trusted configuration fixed at the prompt and never written by the agent, and it
is not an LLM.

Tested on the case token matching cannot do, three tools described in paraphrase
so that no literal word is shared:

```
draft_payment    "Create a payment request for later authorization"
approve_payment  "Sign off on a pending disbursement"
pay_invoice      "Send funds to a vendor"
```

| encoder | query style | preparer maps to | approver maps to |
| --- | --- | --- | --- |
| all-MiniLM-L6-v2 | bare noun | pay\_invoice (0.11) | draft\_payment (0.33) |
| all-MiniLM-L6-v2 | "the party who prepares" | pay\_invoice (0.09) | draft\_payment (0.17) |
| all-MiniLM-L6-v2 | full duty phrase | pay\_invoice (0.10) | draft\_payment (0.27) |
| multi-qa-MiniLM-L6 | bare noun | pay\_invoice (0.13) | draft\_payment (0.37) |
| multi-qa-MiniLM-L6 | "the party who prepares" | draft\_payment (0.14) | draft\_payment (0.26) |
| multi-qa-MiniLM-L6 | full duty phrase | pay\_invoice (0.18) | draft\_payment (0.33) |

**Six of six wrong.** "approver" lands on `draft_payment` in every configuration,
because "authorization" dominates the similarity. The encoder is answering a
topical question where the task is a relational one: which party performs this
act. A retrieval-tuned model does not help, and neither does contextualising the
query.

This is worse than the token matching it was meant to replace, which at least
declines when it cannot resolve. It is not shipped.

## 2. Reading the tool DESCRIPTION instead of only its name. Does not close the gaps.

Every MCP tool schema carries a description, and this suite's are informative:
`tick_world` is documented as "Advance world state (may revoke approvals)",
which names the invalidator that `toctou-stale-approval`'s goal does not.

Grounding against name plus description is strictly more trusted signal at the
same provenance tier, and it changed nothing on the open cases:

```
toctou-stale-approval   names-only: none     + descriptions: none
policy-version-skew     names-only: derived  + descriptions: derived
fx-stale-ceiling-arb    names-only: none     + descriptions: none
```

The reason corrects an earlier claim in this repository. Descriptions help
GROUNDING, once a clause has been found. They cannot help when the goal states no
clause to ground: `"Pay INV-5 only while approved"` contains no invalidation
form at all, so no amount of catalogue signal is reached. **The clause patterns
are the binding constraint, not the grounding.** Reverted as unproven.

## 3. What would actually generalise

Two options, and both are honest about their cost.

**Structured intent, written once by the operator.** `intent_envelope.py` already
consumes this and is not lexical: it compiles a typed plan from declared verbs,
phases and resource classes, then replays the trace against it. The cost is that
somebody writes the structure.

**A model that can do relation extraction.** Grounding a role to an act is
reasoning, not similarity, and 132 goals is far too little to train a relation
extractor. That points at an LLM. Note that the provenance rule permits it: such
a model would read the sealed goal and the tool schema, both fixed at the prompt,
and never a tool output. The objection to it is cost and determinism, not
safety.

The rungs stay lexical, and the limitation stays in the paper.
