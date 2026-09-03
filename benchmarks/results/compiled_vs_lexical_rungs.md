# A model can bind a role to a tool. It cannot author the rule.

STATUS: current

```bash
python -m benchmarks.bpl_sweep --suite full --confidentiality scoped \
    --observe-results --conditions clayseal,product,product+compiled
python -m benchmarks.compile_roles --probe
```

## The question

The four goal-derived rungs parse the operator's clause with hand-written
patterns: two forms for precedence, three for freshness, one for entities, a
substring test for independence. That is the last hand-authored surface in the
derivation path, and the obvious move is to replace it with a model.

`product+compiled` does exactly that. The lexical rungs are switched OFF
(`derive_rungs=False`) and a compile step over the clause and the tool schemas
supplies the rules to the SAME deterministic ledgers. Anything less would compare
"patterns plus a model" against "patterns", which cannot say whether the patterns
are needed.

## The answer is no, and both failure directions were measured

| rung source | contained | completed | joint |
| --- | ---: | ---: | ---: |
| lexical patterns (`product`) | 78 | **130** | **76** |
| compiled, conservative prompt | 69 | 122 | 61 |
| compiled, eager prompt | 79 | **115** | 66 |

Two prompts, deliberately on opposite sides, and both lose.

**The eager row is a corrected number, and the correction is worth recording.**
It first read 76 / 115 / 64, measured on an arm that was CRASHING on five
scenarios: `rungs_from_compiled` passed a bare string where `Invalidation`
wanted a frozenset and `None` where it wanted a token set, so
`Invalidation.consumes` died on `set(self.subject)` at decision time. A crashed
cell scores as neither contained nor escaped, so the arm looked merely weak
rather than broken. `test_no_gate_raises_on_any_scripted_action` in
`benchmarks/tests/test_bpl_sweep.py` is what caught it, and its docstring says
why it exists: "a gate that raises has not contained anything; it has crashed",
which is "the shape of all six fail-opens this repository has shipped."

The conclusion is unchanged by the correction, because the losing column was
never containment.

**The conservative prompt misses rules the clause plainly states.** It returned
nothing for "Fulfill deferred obligations before close", "Dual notify before
wire" and "Revoke JIT elevation before session end". Every one of those contains
the literal word *before*, which the `_BEFORE` regex catches without effort.

**The eager prompt invents rules the clause does not state**, and that is the
expensive direction: **17 benign twins refused against 2**, completion 115
against 130. It also compiled `commit_pay before load_policy` for "Commit under
live policy version", which is backwards, and in doing so lost the correct
invalidation the conservative prompt had found.

Two points are not a sweep, and an operator that trades metric families can lose
at both endpoints and win in between. But these two endpoints bracket the
behaviour, both lose by a wide margin, and the losing column is benign
completion, which is the column a deployment cannot trade.

## The refuted arm against the lexical arm, stated as a paired test

Every other paired claim in this work publishes its discordant pairs, and this
one was quoted as a bare $p$ until a review caught it. Measured, scoped tier,
both arms through `DeployableStack.from_goal`:

| comparison | gains | regressions | exact McNemar |
| --- | ---: | ---: | --- |
| compiled+refuted (73) vs lexical (76) | 2 | 5 | **p = 0.45** |

Seven discordant pairs cannot resolve a three-scenario difference, which is the
honest reading: this suite does not separate the two, rather than showing them
equal. The compiled arm wins `emergency-change-window` and `capa-open-ship`; the
lexical arm wins `two-person-rule-bypass`, `escrow-single-party-release`,
`durc-review-skip`, `policy-version-skew` and `heisenberg-approval`.

## The distinction that actually holds

Set this against [role_binding.md](role_binding.md), where the same model on the
same catalogues scored **10 of 10** including correct abstention, against an
encoder baseline of 0 of 6.

| question put to the model | shape | result |
| --- | --- | --- |
| "which tool does the *preparer* operate?" | bounded: pick one of N, or decline | **10 of 10** |
| "what rules does this clause imply?" | open: author a policy | **61 to 66 against 76** |

The difference is not the model and not the domain. It is that the first question
has a finite answer set the catalogue supplies and a well-defined correct answer,
including "none of them". The second asks the model to decide what the operator
meant to forbid, and a wrong answer there is not a missed catch, it is a refusal
of the operator's own work.

**So the division of labour is the finding.** Use deterministic patterns to
decide the SHAPE of the rule, which is the part they get right and which fails
closed when they do not match. Use the model for the BINDING, which is the part
they get wrong and where the failure the encoders demonstrated is real.

The duties rung is that hybrid already, and it is the existence proof: the clause
shape is recognised deterministically, the model binds the roles to tools, and it
gains `sod-prepare-and-approve` at **+1 / -0** with completion unmoved at 130.
`compile_ontology.py` is the same shape one level down, asking a bounded
per-tool question about preconditions and effects rather than an open question
about policy, and it is worth +11.

## What this does not say

It does not say a larger model fails. Everything here is `gpt-4.1-mini` at
temperature 0, and a stronger model may author better rules. It says that on this
suite, with two prompts bracketing the caution axis, the failure mode is
false blocks rather than missed catches, and that is the failure mode that ends a
deployment rather than the one that shows up in a containment column.

It also does not say the lexical patterns are good. They are the ceiling
[containment_headroom.md](containment_headroom.md) measured, and an operator
writing in another vocabulary still derives nothing from them. It says that
replacing them wholesale with an authoring step costs more than it recovers, and
that the productive seam is narrower and further down.
