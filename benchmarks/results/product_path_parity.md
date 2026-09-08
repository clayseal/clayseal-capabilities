# The measured system and the shipped system were not the same system

STATUS: current

```bash
python -m benchmarks.bpl_sweep --suite full --json /tmp/bpl.json
```

## The defect

Every broker arm in this suite calls `scen.make_broker()`, which constructs a
`SessionBroker` directly. **No scenario went through
`DeployableStack.from_goal`**, which is the only factory the CLI, `docs/API.md`
and the README expose.

Worse, that factory could not have reproduced the published arm even if a
scenario had used it. `from_goal` had no parameter for `obligations`,
`freshness`, `identity` or `entities`. All four were declared on the broker as
`Any | None = None` with a comment telling a caller to build one, and **nothing
anywhere in `clayseal/` ever called the `derive_*` functions that fill them**.
The only caller was `bpl_sweep.py`, which set the attributes by hand on a broker
it had built itself.

So the joint containment this repository published came from a configuration no
supported code path could construct, and a deployment following the documented
CLI got the base gateway. `docs/API.md:77` was candid about it ("Off unless a
caller sets it, because deriving a rule from a sentence is inference"), but
nothing measured the size of the gap.

**It was 21 scenarios.**

## The fix

`clayseal/capabilities/derivation.py` reads the four rungs from the two trusted
inputs, the sealed goal and the tool catalogue, and `from_goal` calls it by
default. A rung derives nothing unless the goal names its constraint in the
catalogue's vocabulary, so the failure mode of deriving is an absent rule rather
than a spurious one.

The `product` arm below builds each scenario through that factory. It exists so
this cannot silently come apart again.

| arm | contained | completed | joint |
| --- | ---: | ---: | ---: |
| `none` (allow-all) | 0 | 132 | 0 |
| `deny-all` | 132 | 0 | 0 |
| `clayseal` base | 54 | 130 | 52 |
| hand-wired ladder (`clayseal+identity`) | 75 | 130 | 73 |
| **`product`, before this work** | 54 | 130 | **52** |
| **`product`, now** | 75 | 130 | **73** |
| **`product+ontology`** | **86** | 130 | **84** |

`product` is at exact parity with the hand-wired ladder, +0 / -0.

With the scoped flow tier, which is the published configuration, the
`product` arm is **78 / 130 / 76**, matching it row for row, and the
catalogue-derived rungs take it to **90 / 130 / 88**
([role_binding.md](role_binding.md)).

## Three defects the parity arm exposed, none of which a test was failing on

**The intent envelope's `tools` field was being enforced as an entity list.**
`bindings_from_intent` excluded only `verbs` and treated every other list-valued
key as a list of counterparties, at `declared=True`, which is the provenance
level that DENIES rather than escalating. Every MCP fixture ships
`structured_intent={"kind":..., "verbs":[...], "tools":[...]}`, so the tool
allow-list governed argument slots and refused benign work: 1 false block in 9 on
`mcp_attack`. Now excluded via `_ENVELOPE_FIELDS`.

**`refuse_credential_payloads` was measured, documented and unreachable.** It
denies a consequential action whose payload carries a credential literal, at a
measured 0 of 761 benign string arguments. `from_goal` had no parameter for it,
so no deployment built through the supported factory could turn it on. Its own
code comment names the scenario it was written for, `integration-invoice-cover`,
which is exactly the scenario the parity arm lost until this was exposed.

**The new arm scored 0 contained and 132 completed on its first run**, which is
the allow-all profile. `is_broker_arm` did not know the name, so `apply_call`
fell through to the no-gate branch and the arm measured an undefended run. That
is the failure this repository documents as characteristic, and the permanent
`none` and `deny-all` rows are what made it obvious in one glance instead of
becoming a published number.

## The ontology arm, and what may be quoted from it

`product+ontology` attaches a `PreconditionLedger` over the compiled tool
ontology. The operators come from `compile_ontology.py`, which reads the tool
SCHEMAS alone, offline and once per catalogue, and they are cached in
`_ontology_cache.json`; this arm makes no model call. `preconditions.refuted_by`
then drops every precondition the known-good trace violates.

Against `product`: **+11 contained, 0 regressions, exact McNemar p = 0.000977.**
Completion is unmoved at 130.

The eleven are `toctou-stale-approval`, `spoof-order-cancel`,
`checklist-interrupt-skip`, `kyc-expired-continue`, `capa-open-ship`,
`mel-fly-expired`, `shared-ref-cross-tenant`, `fx-stale-ceiling-arb`,
`summary-strips-forbid`, `launder-then-alias-quorum` and
`cover-then-heisenberg-pay`. Two of them, `toctou-stale-approval` and
`fx-stale-ceiling-arb`, are the cases
[generalizing_derivation.md](generalizing_derivation.md) recorded as underivable
by grounding against tool descriptions. Nothing here reads a goal sentence, which
is the point: this is precedence recovered from the catalogue, so it reaches a
deployment whose operator writes in a vocabulary no lexical rung can parse.

**Do not quote the completion column as evidence.** Each catalogue in this suite
ships exactly one benign trace, its own compliant twin, so the traffic that
refutes the artifact is then the traffic scored, and 130 is guaranteed by
construction. The containment column is honest, because nothing in validation
ever sees an attack. A deployment validates against its own logs and afterwards
serves different traffic, so it does not inherit this defect, but this suite
cannot measure that and does not claim to.

## Parity of the promoted ledger, checked rather than assumed

`clayseal/capabilities/preconditions.PreconditionLedger` was promoted out of
`benchmarks/precondition_rung.py`. The two were run side by side over every
script of all 132 catalogues carrying a compiled ontology: **4,693 decisions
compared, 4,693 agree, 0 disagree.**
