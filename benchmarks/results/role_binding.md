# Binding a role to a tool: the route that was priced and never run

STATUS: current

```bash
python -m benchmarks.compile_roles --probe
python -m benchmarks.bpl_sweep --suite full --confidentiality scoped \
    --observe-results --conditions product,product+ontology,product+duties,product+all
```

## What was refuted, and what that refutation covers

[generalizing_derivation.md](generalizing_derivation.md) records route 1 as dead:
`"approver"` resolves to the drafting tool in **6 of 6** configurations, so the
rungs stay lexical. `paper/body.tex` reproduces that conclusion.

Read the setup before inheriting it. Those six cells are two bi-encoders from one
MiniLM family, both under 22M parameters, compared by cosine similarity across
three query framings. No cross-encoder, no NLI model, no instruction-tuned
embedder, and **no LLM**. An encoder answers *what is this text about*, and a
drafting tool and an approving tool are both about payment authorization, so the
question the encoder can answer does not separate them.

The same document says this itself, in its closing section: the mapping "is
reasoning, not similarity", it "points at an LLM", and "The objection is cost and
determinism, not safety." The route was named, argued to be permitted under the
provenance rule, and then not run.

## Running it

`benchmarks/compile_roles.py`, `gpt-4.1-mini`, temperature 0, one call per
(catalogue, clause), cached. Input restricted to tool name, description and
parameter names by `_schema_only`, which asserts the restriction in code.

The probe uses the **same three tools in the same deliberate paraphrase** the
encoders were refuted on, so this is like-for-like and not an easier restatement.

| configuration | correct |
| --- | ---: |
| paraphrased, bare nouns (`preparer`, `approver`) | 2 of 2 |
| paraphrased, duty phrase | 2 of 2 |
| `maker` / `checker` | 2 of 2 |
| German (`Ersteller`, `Genehmiger`) | 2 of 2 |
| **CONTROL: catalogue where no tool matches** | **2 of 2 declined** |
| **total** | **10 of 10** |

Encoder baseline on the same tools: **0 of 6**.

**The control is what makes this a measurement.** A resolver that always answers
is a coin that has learned which way to land, so the probe includes a catalogue
of reads where the correct output is no binding at all. It declined both.

The German row matters beyond its cell. `body.tex` lists "a goal in another
language derives nothing" as a limitation of the lexical rungs. It is a
limitation of lexical matching, not of the problem.

## End to end, and the three wrong designs it took to get there

Binding the role was the easy half. Enforcing it took three attempts, and the
first two are recorded because each looked correct and measured worse.

| enforcement | joint | vs `product` |
| --- | ---: | --- |
| refuse the second half of the pair | 76 | +1 / **-1** |
| gate the protected act, refusing incomplete controls too | 75 | +1 / **-2**, completion 130 to 128 |
| **gate the protected act, collapse only, never refuse a signature** | **77** | **+1 / -0** |

**Attempt one walked into the trap `identity.py` documents.** That file records
"refuse the ACT, never the signature ... measured three times in this work before
it was believed." Refusing `seller_release` when the same party released as buyer
leaves `seller` unset, the disbursement still lands, and
`escrow-single-party-release` scores an incomplete control exactly like a
collapsed one. A contained scenario became an escaped one. That is the fourth
measurement of the same lesson.

**Attempt two over-corrected.** Requiring both halves before the gated act reads
as the stricter and therefore safer rule. Measured, it refused benign work on
`temp-elevate-standing` and `dual-notify-omission` and cost two completions for
one containment.

**Attempt three** gates only the protected act, refuses only on collapse, and
never refuses a signature when a separate act is gated.

## Result

132 paired scenarios, scoped flow tier, every arm built through
`DeployableStack.from_goal`.

| arm | contained | completed | joint |
| --- | ---: | ---: | ---: |
| `none` (allow-all) | 0 | 132 | 0 |
| `deny-all` | 132 | 0 | 0 |
| `clayseal` base | 57 | 130 | 55 |
| `product` (= paper Table 1) | 78 | 130 | 76 |
| `product+ontology` | 89 | 130 | 87 |
| `product+duties` | 79 | 130 | 77 |
| **`product+all`** | **90** | **130** | **88** |

`product+all` against `product`: **+12 gains, 0 regressions, exact McNemar
p = 0.00049**. Benign completion is unmoved at 130 in every arm.

Every arm here is built by `DeployableStack.from_goal`, including both compiled
rungs, which are passed to the factory rather than attached to a finished broker.
Attaching them afterwards gives the same numbers to the digit, and that is worth
saying because it is the weaker measurement: it would exercise the ledgers while
leaving the product's own construction path untested, which is exactly the defect
[product_path_parity.md](product_path_parity.md) exists to record.

The two catalogue-derived rungs **compose additively**, 11 and 1 giving 12, which
was a question rather than an assumption: they read different things, and nothing
guaranteed their gains were disjoint.

## What may not be quoted from this

**The duties rung moves one scenario.** One discordant pair cannot reach
significance and its p of 1.0 says so. `sod-prepare-and-approve` is the scenario
the lexical rung provably could not reach, which is why it is interesting, but a
single scenario is an existence proof and not a rate.

**Completion 130 on the ontology arm is guaranteed by construction.** Each
catalogue ships one benign trace, so validation and scoring see the same traffic.
Containment is honest, because validation never sees an attack. See
[product_path_parity.md](product_path_parity.md).

**The principal is declared, not attested.** An agent that calls `set_persona`
and lies defeats this rung, which catches process error and an attacker who does
not trouble to lie. Closing it needs an attested principal the orchestrator sets,
which is a property of the deployment.

**Two of the four duty scenarios still derive nothing.**
`custody-seal-break-reseal` compiles to no rule: it is a dual-control obligation,
a witness must attest between the break and the reseal, and the compiler returned
an empty `witness_required`. `two-person-rule-bypass` names a gated act and no
pair. The role binding works; a witness-between-acts rule is a different rule and
is not built.
