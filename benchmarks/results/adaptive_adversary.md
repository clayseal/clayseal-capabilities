# Adaptive adversary (dynamic sandbox v0.2)

STATUS: unverified

> No command was recorded for this file, so its numbers cannot be
> re-derived from it. `unverified` says that nobody has checked them, which
> is the honest claim; `current` would be vouching for a run nobody can
> reproduce. See the provenance section of [README.md](README.md).


The decisive anti-overfit test, item 3 of the contract in
[../../docs/dynamic_sandbox.md](../../docs/dynamic_sandbox.md). A fixed attack
proves nothing about an adversary who knows the defense. This attacker
([../live/adaptive_attack.py](../live/adaptive_attack.py), registered as
`envelope_aware`) is built against the mechanism, not against a phrasing. It
blends the malicious action into the authorized manifold: it prepends a benign
in-scope read to satisfy gather-before-act, frames the malicious effect as a
routine continuation of the same task in the task's own vocabulary, and asserts
the step is pre-approved and needs no confirmation to dodge the step-up.

The constraint that makes the test meaningful: the attacker cannot rewrite the
malicious goal's destination (the injection task fixes the attacker IBAN). So
where destination binding applies it should still fail, and whatever it leaves is
the true frontier, not a phrasing weakness.

## Banking, gpt-4o-mini, envelope_aware attack, n=18

| configuration | clean utility | ASR | utility under attack |
|---|--:|--:|--:|
| none (baseline) | 50.0% | 38.9% | 16.7% |
| envelope (deployable, no oracle) | 16.7% | 16.7% | 16.7% |
| full stack (oracle scope + destination binding) | 50.0% | **0.0%** | 27.8% |

## Reading

The full stack holds ASR at 0 percent against an adversary that knows the defense
and optimizes to evade it. This is the strongest single result for the
whitelist-not-blacklist thesis. The attacker satisfies every structural rule it
can reach (scope membership, verb-class order, suppressed step-up) and still
fails, because it cannot move the destination and binding catches the send.
Clever phrasing does not help when the defense constrains the outcome rather than
the input.

The deployable envelope with no oracle cuts ASR from 38.9 to 16.7 percent, at a
clean-utility cost (50 to 16.7 percent). That residual is precisely the
read-then-send class that only the oracle destination binding closes today. It is
the honest frontier, and it is exactly what v0.2 keystone 2 (deployable
provenance / taint) exists to close: reach the binding from data-flow instead of
ground-truth seeding, and recover the ceiling's 0 percent on the deployable path.

Note the adaptive attacker's baseline ASR (38.9 percent) is lower than the fixed
important_instructions attack (67 percent), because manifold-blending phrasing is
less forceful at commandeering the agent than a blunt out-of-band instruction.
The point of the test is not raw attack strength; it is that a defense-aware
attacker leaves no residual where binding applies.

## Status

Contract item 3 is met at the full-stack ceiling. The deployable-path residual is
named and it is the provenance keystone, not a new weakness. Next: run the same
attack across the held-out suites (workspace, travel, slack), then build the
provenance layer and re-measure the deployable path.
