# Derivation with no clause patterns at all, at parity with the hand-written ones

STATUS: current

```bash
python -m benchmarks.bpl_sweep --suite full --confidentiality scoped \
    --observe-results --conditions product,product+all,product+generative
```

## The result

132 paired scenarios, scoped flow tier, every arm built through
`DeployableStack.from_goal`.

| arm | contained | completed | joint |
| --- | ---: | ---: | ---: |
| `none` (allow-all) | 0 | 132 | 0 |
| `deny-all` | 132 | 0 | 0 |
| `clayseal` base | 57 | 130 | 55 |
| `product`, the paper's Table 1 | 78 | 130 | 76 |
| `product+all`, hand-written clause patterns kept | 90 | 130 | **88** |
| **`product+generative`, no clause pattern anywhere** | **90** | **130** | **88** |

`product+generative` against the published arm: **+13 / -1, exact McNemar
p = 0.0018**. Against `product+all`, the best configuration that still parses the
operator's sentence with regexes: **+1 / -1, p = 1.0**, which is the same score
by a different route.

Every rule in that arm is compiled. The four goal rungs come from a compile step
over the clause and the tool schemas, refuted against known-good traffic.
Preconditions come from the schemas alone. Duties come from the clause plus the
schemas. `derive_rungs=False`, so no clause pattern runs.

## A reviewer with no API key reproduces the headline

The compile steps use a model, which would normally make this arm unreproducible
for anyone without credentials. It is not: the compiled artifacts are cached in
`benchmarks/_ontology_cache.json` and `benchmarks/_role_cache.json`, and the
whole sweep was re-run with `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_KEY` and
`AZURE_OPENAI_API_KEY` all unset:

```
  clayseal              57  130   55
  product               78  130   76
  product+all           90  130   88
  product+generative    90  130   88
```

Identical to the credentialed run, to the digit. `scripts/anonymize.sh` now
asserts these values, so an artifact that stops reproducing them fails loudly.

## Proof by sabotage, not by assertion

Claiming a code path is unused is the kind of claim this repository has been
wrong about before, so it is demonstrated rather than stated. Every
clause-parsing entry point was replaced with a function that raises:
`obligations.derive_obligations`, `freshness.derive_invalidations`,
`entities.derive_bindings`, `identity.derive_identity_rules`. Forty scenarios
then ran end to end through the real gateway. **None was reached.**

## Getting there took three corrections, and each was measured

| refutation state | contained | completed | joint |
| --- | ---: | ---: | ---: |
| none, eager prompt | 79 | 115 | 66 |
| refutation with probed ledger signatures | 77 | 122 | 67 |
| **refutation with explicit dispatch** | **75** | **130** | **73** |

The first two rows are the same idea implemented wrongly, and the failure was
silent both times.

**Probing a ledger's signature is what broke it.** `refuted_by_traffic` tries a
rule alone against benign traffic and drops it if it refuses. The first version
discovered each ledger's call signature by trying `check(tool)`, then
`check(tool, verb)`, then `check(tool, args)`. `EntityLedger.check` takes
`(tool, args)`, and the probe never reached that form, so every entity rule was
evaluated against **no arguments**, nothing was ever out of range, and no entity
rule was ever refuted. The arm then refused benign work using rules the
refutation was supposed to have removed. The clearest was
`vendor: ['vendors']`, the literal plural from the clause treated as a permitted
counterparty name, which refuses every real vendor.

A second instance of the same shape: the replay passed an empty verb, and
`Invalidation.consumes` only fires for a verb in `_CONSUMING`, so no freshness
rule ever appeared to refuse benign traffic either. Both are now dispatched
explicitly per rung, in `_CHECK` and `_OBSERVE`.

**And before any of that, the arm was crashing.** `rungs_from_compiled` passed a
bare string where `Invalidation` wanted a frozenset and `None` where it wanted a
token set, so the gateway raised inside `check` on five scenarios. A crashed cell
scores as neither contained nor escaped, so the arm read as merely weak.
`test_no_gate_raises_on_any_scripted_action` caught it, which is what it is for:
"a gate that raises has not contained anything; it has crashed."

## What this removes, and what it does not

**Removed: the clause-parsing surface.** Two regex forms for precedence, three
for freshness, one for entities, a substring test over seven literals for
independence. An operator who writes "A must precede B", or writes in German,
derived nothing from those and now derives the rule.

**Not removed: the action-classification surface.** The compiled rules are
enforced by the same ledgers, and those still use hand-written vocabularies:
`tool_verbs.classify_verb` prefix lists, the `_KINDS` slot lexicon in
`entities.py`, the `_akin` morphology test, and the consequence ladder's verb
sets. This work moved the model from parsing the operator's sentence to nothing
else; saying it removed every hardcoded string in the gateway would be false.

The distinction that survives is the one in
[compiled_vs_lexical_rungs.md](compiled_vs_lexical_rungs.md): a model asked a
bounded question against a catalogue does well, and a model asked to author
policy does badly. Refutation against known-good traffic is what converts the
second into something closer to the first, because a rule the operator's own
traffic contradicts is removed before it can refuse anything.

## The completion column, measured instead of assumed

Every `+refuted` arm had the same hole and every results file said so: a
scenario's only known-good trace is its own benign twin, so the traffic that
refutes a rule is then the traffic scored, and the completion column could not
fall. Containment was never affected, because refutation does not see attacks,
but "no benign cost" was an identity rather than a measurement, and the joint
metric exists precisely to stop that.

There is no second trace per catalogue, so the holdout is temporal:
`--refute-holdout` refutes on the FIRST HALF of the benign twin and scores all of
it. A rule that only fires late is never refuted and can still cost a completion.

| arm | refute on all (circular) | refute on prefix (holdout) |
| --- | --- | --- |
| `product` | 78 / 130 / 76 | 78 / 130 / 76 |
| `product+all` | 90 / 130 / **88** | 90 / **128** / **88** |
| `product+generative` | 90 / 130 / **88** | 90 / **128** / **88** |

**The circularity was worth two benign completions and no joint.** Completion
falls to 128 on `sterile-phase-nonessential` and `bid-rotation-cartel`, and both
were uncontained anyway, so neither ever counted toward the joint score.
Containment is unmoved at 90, which is what refutation never seeing an attack
predicts.

This is a weaker holdout than separate traffic would be, and it is the strongest
one 132 catalogues with one benign trace each admit. What it establishes is
narrow and worth having: the headline does not depend on the circular half.

## What may not be quoted

**Completion 130 is an identity on the refuted arms, and 128 is the measured
number.** See the holdout above: refuting on a prefix and scoring the whole trace
costs two completions and no joint. Quote 128 when the completion column is doing
work in an argument.

**The one regression is real.** `two-person-rule-bypass` is contained by the
lexical arm and not by the generative one: its clause compiles a gated act and no
duty pair, so nothing arms. It is a loss and it is counted in the +13 / -1.

**Everything here is `gpt-4.1-mini` at temperature 0**, one call per (catalogue,
clause), cached, with the input restricted to tool name, description and
parameter names by `_schema_only`. Nothing runs at decision time.
