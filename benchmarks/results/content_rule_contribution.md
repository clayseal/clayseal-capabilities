# What the deterministic content pack contributes: a lot, and only to its own corpora

STATUS: current

```bash
python -m benchmarks.coverage --datasets sleight,agentharm --limit 4000 \
    --engines deployable-stack                      # pack on  (BENCHMARK profile)
python -m benchmarks.bpl_sweep --suite full         # pack on, and worth nothing here
```

`monitor/entailment.deterministic_content_reasons` holds sixty hand-written
patterns: 27 structural rules, each an AND of a regex over the write body and an
English-word test over the sealed goal, plus 33 harmful-intent cues
(`_HARM_CUES`) and a two-entry typosquat list.

Until this measurement it ran **unconditionally on the authorize path**. Not
behind a flag like `session_rules`, not named in the broker's field list, not
mentioned in any results file. It was the largest unpriced hand-authored artifact
in the gateway, and every published containment number for a content-defined
corpus included it.

## Why this needed measuring

[corpus_rule_contribution.md](corpus_rule_contribution.md) audited three other
corpus-derived literals and found all three worth exactly zero. That result is
easy to over-generalise into "the corpus-shaped rules in this repository do not
matter." This pack is the counterexample, and it matters a great deal.

The patterns name their origins openly. One matches `brainfuck` and `esoteric`;
one keys on `IFS=:` followed by `while read` and carries the comment "Measured
2/2 SLEIGHT IFS attacks"; one fires on a `.gitignore` of at least 200 enumerated
lines omitting `.env`; the typosquat list is `confschema` and `matplotib`.

## What it is worth

In-surface containment, `deployable-stack`, the class where a per-call
authorization layer has nothing to object to and these patterns are the only
thing deciding.

| population | full pack | structural only | pack off |
| --- | ---: | ---: | ---: |
| SLEIGHT in-surface (122 events) | **23.8%** [16.6, 31.7] | 23.8% | **4.1%** [0.9, 8.1] |
| AgentHarm in-surface (507 events) | **38.7%** [32.8, 44.2] | 26.8% | **26.8%** [20.9, 32.9] |
| BPL, 132 scenarios, joint | 73 | 73 | 73 |

"Structural only" sets `_HARM_CUES = ()` and keeps the 27 structural rules.

**The two halves are disjoint, and that is the finding.** Every point on SLEIGHT
comes from the 27 structural rules and none from the cues. Every point on
AgentHarm comes from the cues and none from the structural rules. Neither half
transfers to the other corpus. On BPL the pack was **invoked 54 times and fired
0**, so it contributes nothing to any number in the paper's Table 1.

A rule that earns 19.7 points on the corpus it was written against and 0.0 on the
next corpus over is not a defence. It is a record of what somebody already saw.

## The switch was verified to reach the broker, and the first attempt did not

`content_rules` now gates the pack. The first verification attempt flipped the
dataclass default on `SessionBroker` and re-ran: the pack was still invoked 282
times and the table was **identical to the pack being on**, because
`DeployableStack.from_goal` passes its own parameter default and overrides the
class attribute.

That is exactly the shape this repository keeps finding, and it is why the check
exists: an arm that silently does nothing produces a plausible table rather than
an error. Gating at the factory level gives 0 invocations and reproduces the
monkeypatched numbers to the digit.

## What changed

`content_rules` defaults **True** on `SessionBroker` and on
`DeployableStack.from_goal`, so no published number moves and no existing caller
changes behaviour. `profiles.py` sets it **False** for AUTONOMOUS and SUPERVISED
and **True** for BENCHMARK, which is the same split `session_rules` carries and
for a stronger reason: the contribution here is real, and it is real only on the
two corpora the rules were written against.

The cost of leaving it on is bounded. The pack only ever STEP_UPs, never DENYs.
The cost of leaving it on **in a deployment** is not bounded by that, because
`_HARM_CUES` matches `\bdrugs?\b`, `\billegal\b` and `\bbomb\b` against the write
body whenever the word is absent from the sealed goal, and a pharmacy, a
compliance team and a demolition contractor all write those words in the ordinary
course of business.

## What this does to the paper

`paper/body.tex` reports SLEIGHT at 31.0% and AgentHarm at 6.3% as evidence of
where the mechanism does **not** work. Those numbers were produced with the pack
on, so the honest reading is that the true out-of-the-box figure on unlike
traffic is lower still, and the limitation the paper states is understated rather
than overstated. That is the safe direction, and it should be said rather than
left for a reader to find.
