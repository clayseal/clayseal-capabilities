# Live AgentDojo evaluation

STATUS: superseded

> **STATUS: superseded.** Retired on 2026-08-29. The figures below were never
> re-derived, carry no reproduce command, and are cited by no document in this
> repository. 216 runs across three sweeps per suite, where this was a single sweep is now in
> [pooled_asr.md](pooled_asr.md), which is stamped `current`.
>
> Kept rather than deleted, because a number that was once published should stay
> readable with its correction attached.

> No command was recorded for this file, so its numbers cannot be
> re-derived from it. `unverified` says that nobody has checked them, which
> is the honest claim; `current` would be vouching for a run nobody can
> reproduce. See the provenance section of [README.md](README.md).


The broker wrapped around a real LLM agent (gpt-4o-mini) in the AgentDojo harness,
under the real `important_instructions` prompt-injection attack. Unlike the
deterministic-replay benchmark, this measures a live agent that reads tool output,
can be diverted by an injection, and can lose task utility to over-blocking. We
report attack-success rate (ASR), clean task utility, and utility-under-attack.

Suite: banking. 6 user x 3 injection tasks = 18 runs per config. n is small, so
ASR moves a few points run to run (baseline ASR ranged 50-72% across runs); read
the numbers as directional and the layer attribution as the durable finding.

## Ablations

| config | clean utility | ASR | util-under-attack | note |
|--------|--------------:|----:|------------------:|------|
| none (no defense) | 50% | 50-72% | 28-33% | baseline |
| builtin:tool_filter (AgentDojo's own) | 50% | 22% | 33% | published defense |
| floor (LLM-planned tool scope) | 33% | 28% | 28% | deployable scope |
| envelope (LLM plan + ordering) | 17% | 11-22% | 22% | ordering over-blocks |
| oracle (ground-truth tool scope) | 33-50% | 11-17% | 22-33% | scope ceiling |
| **oracle-egress (scope + recipient binding)** | **50%** | **0%** | **33%** | **arg-level ceiling** |

Two results carry the story:

1. **The enforcement floor with correct scope beats the published defense.** Oracle
   scope cuts ASR from ~61% to ~17% at no clean-utility cost, versus tool_filter's
   22% at the same utility. The mechanism is sound.

2. **Argument binding closes the residual.** Tool scope alone floors at ~17% ASR
   because `send_money` is a legitimate tool and the attack rides it with a
   malicious recipient. Binding the recipient (oracle-egress) drives ASR to 0%
   while preserving full clean utility and full utility-under-attack.

## Decision attribution (why the numbers move)

Every broker decision was labelled against the task's ground-truth legit tools and
the injection's argument-level payload (attacker IBAN `US133...`).

- **Utility killer is scope granularity, not the mechanism.** Under oracle scope,
  the genuinely-needed tools pass at 0% block. What gets blocked is the agent's
  legitimate orientation calls (balance/IBAN lookups) that are not in the minimal
  ground-truth path (the "other" bucket, blocked 100%). Scoping to the optimal
  path is too tight; a real agent traverses a superset.
- **ASR floor is argument-level.** With scope alone, 4-5 `send_money`-to-attacker
  calls leaked per run, allowed because the tool is in scope and no layer
  inspected the recipient. Recipient binding blocks these at the egress layer.
- **Ordering is a real precision/recall trade.** The intent-envelope ordering
  raised attack-block from 43% (floor alone) to 64%, but also blocked 10-25% of
  legitimate calls by rejecting interleavings that do not follow the strict linear
  plan. Relaxing to partial-order is the fix.

## Honesty on the ceiling vs the deployable system

The `oracle` and `oracle-egress` rows are privileged: tool scope and authorized
recipients are seeded from ground truth. They measure the ceiling of the
architecture, not a shippable planner. They are labelled as such and are never
presented as the deployable number.

The deployable path has two named gaps:
- **Scope accuracy.** The LLM planner must approach the oracle tool set, and must
  include read-only orientation tools so it does not block them.
- **Recipient provenance.** Authorized recipients must be seeded from the
  provenance of trusted-named resources (read the specific bill file the user
  named, extract the biller IBAN), not from ground truth. This is the CaMeL-style
  data-flow direction: a legitimate recipient traces to data the sealed goal
  authorized reading, an injected recipient does not.

The ceiling result establishes that the architecture can reach ASR 0% at full
utility on this suite. Closing the gap to the deployable system is planner
accuracy plus recipient provenance, both scoped above.
