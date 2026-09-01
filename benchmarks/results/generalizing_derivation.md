# What it would take to generalize goal derivation. Four attempts, measured.

STATUS: current

The five goal-derived rungs parse a clause from the sealed goal and ground each
side against the tool catalogue by token overlap. That is lexical, and lexical
does not generalize: `"SoD: separate preparer and approver"` cannot reach
`draft_payment`, because "preparer" and "draft" share no token. A goal written in
another language, or in an operator's own house vocabulary, derives nothing.

This is a map of the design space, with the evidence for each route. **None of
the four shipped.** The reason they did not is the useful part, because it says
precisely what a deployment must supply for a general mechanism to exist.

## 1. Sentence embeddings for grounding. REFUTED.

Embed the role phrase and each tool's description, ground by cosine similarity.
Not an LLM, runs offline on CPU, and provenance-clean: a tool schema is trusted
configuration fixed at the prompt and never written by the agent.

Tested on the case token matching cannot do, three tools described in paraphrase
so no literal word is shared with the role:

```
draft_payment    "Create a payment request for later authorization"
approve_payment  "Sign off on a pending disbursement"
pay_invoice      "Send funds to a vendor"
```

| encoder | query | preparer resolves to | approver resolves to |
| --- | --- | --- | --- |
| all-MiniLM-L6-v2 | bare noun | pay\_invoice (0.11) | draft\_payment (0.33) |
| all-MiniLM-L6-v2 | "the party who prepares" | pay\_invoice (0.09) | draft\_payment (0.17) |
| all-MiniLM-L6-v2 | full duty phrase | pay\_invoice (0.10) | draft\_payment (0.27) |
| multi-qa-MiniLM-L6 | bare noun | pay\_invoice (0.13) | draft\_payment (0.37) |
| multi-qa-MiniLM-L6 | "the party who prepares" | draft\_payment (0.14) | draft\_payment (0.26) |
| multi-qa-MiniLM-L6 | full duty phrase | pay\_invoice (0.18) | draft\_payment (0.33) |

**Six of six wrong.** "approver" lands on `draft_payment` in every configuration
because "authorization" dominates the similarity, and a retrieval-tuned encoder
does not help. The encoder answers *what is this text about*; the question is
*which party performs this act*. Those are different, and no amount of query
engineering closed the gap. This is worse than the token matching it would
replace, which at least declines when it cannot resolve.

## 2. Grounding against the tool DESCRIPTION. No effect on the open cases.

Every MCP schema carries a description, and this suite's are informative:
`tick_world` is documented as "Advance world state (may revoke approvals)",
naming the invalidator that `toctou-stale-approval`'s goal leaves unnamed.

Strictly more trusted signal at the same provenance tier, and it changed nothing:

```
toctou-stale-approval   names only: none      + descriptions: none
policy-version-skew     names only: derived   + descriptions: derived
fx-stale-ceiling-arb    names only: none      + descriptions: none
```

This corrects an earlier claim of ours. Descriptions help GROUNDING, once a
clause has been found. They are never reached when the goal states no clause to
ground: `"Pay INV-5 only while approved"` contains no invalidation form at all.
**The clause patterns are the binding constraint, not the grounding.**

## 3. Precedence from the schema's data dependencies. 6 of 132.

The most promising route, because it needs no goal sentence whatsoever. A tool
requiring `draft_id` consumes an entity that some other tool produces, so the
precedence relation sits in the schema:

```
draft_payment(payee, amount)        produces a draft
approve_payment(draft_id)           requires one
```

Direction is recoverable without prose: a tool cannot be handed the identifier of
the thing it creates, so the tool that *requires* the id is the consumer and the
tool named for the entity that does *not* require it is the producer.

Undirected, the rule fires on 9 of 132 scenarios and gets direction wrong often,
proposing `approve_draft -> draft_payment` and `reply_ticket -> get_ticket`.
Directed, it yields 11 dependencies across **6 of 132 scenarios**, and several
remain spurious because read-only tools mention the entity too:

```
draft_payment -> approve_payment   (correct)
draft_trace   -> draft_payment     (spurious; a trace tool produces nothing)
capa_status   -> open_capa         (spurious; same shape)
```

Filtering those needs an observer lexicon, which is the lexical dependency this
route was meant to escape. Coverage is also below the goal-clause rung it would
replace, which reaches 10 scenarios.

## 4. Planning over a declared ontology. BLOCKED, and this is the finding.

`monitor/ontology.py` already models tools in PDDL terms: preconditions, add
effects, delete effects, reversibility. With that, plausible completions of a
goal are computable, an observed sequence can be scored against them, and
severity follows from declared irreversibility. It needs no natural language at
all, which makes it the only route here that generalizes by construction.

**Zero of 133 scenarios declare an ontology.**

So a distribution over plausible action sequences could be built and could not be
evaluated. Its numbers would be a property of an ontology we had written for the
occasion. That is exactly the failure `adequacy.md` exists to catch, turned on
our own proposal: a corpus that cannot exercise a mechanism does not return a low
score, it returns a plausible one.

## What this says a deployment must supply

The lexical rungs work on goals whose vocabulary matches the tools. Generalizing
past that needs one of three things, and every one is a property of the
deployment and not of the algorithm:

1. **A declared ontology.** Preconditions and effects per tool. The library
   consumes it today and nothing populates it. This is the strongest option and
   the one with a real integration cost.
2. **Structured intent.** `intent_envelope.py` already compiles a typed plan from
   declared verbs, phases and resource classes, and is not lexical. Somebody
   writes the structure once per task type.
3. **A model that can do relation extraction.** Grounding a role to an act is
   reasoning, not similarity, and 132 goals will not train one. This points at an
   LLM. Worth stating plainly: the provenance rule *permits* it, since such a
   model reads the sealed goal and the tool schema, both fixed at the prompt, and
   never a tool output. The objection is cost and determinism, not safety.

The rungs stay lexical. The limitation stays in the paper, and it is now a
measured limitation with four routes priced rather than an admission.
