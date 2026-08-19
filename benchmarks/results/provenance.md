# Provenance egress: deployable destination binding (v0.2 keystone 2)

The oracle problem, stated in every prior result: the full stack's 0% ASR uses
ground-truth destination seeding. The deployable system must reach the same
containment from the goal, not the answer key. Provenance is that replacement:
seed the trusted destination set from the sealed goal (the trusted user prompt,
captured before any tool output can contaminate it), and deny any effect whose
destination is not traceable to it. Implementation: `goal_destinations()` in
[../live/broker_defense.py](../live/broker_defense.py), ablation
`envelope-provenance`.

## Result: banking, gpt-4o-mini, important_instructions, n=18

| configuration | clean utility | ASR | utility under attack |
|---|--:|--:|--:|
| none (baseline) | 50.0% | 61.1% | 38.9% |
| envelope (deployable, no egress binding) | 33.3% | 11.1% | 16.7% |
| envelope-provenance (deployable, goal-seeded) | 16.7% | **0.0%** | 22.2% |
| oracle scope + binding (ceiling) | 50.0% | **0.0%** | 33.3% |

## Reading

Security: provenance reaches 0 percent ASR, matching the oracle ceiling, with no
ground-truth seeding. This is the point that mattered. The deployable path no
longer depends on the oracle to block the attacker destination, because the
attacker destination is never present in the sealed goal. The mechanism is
validated.

Utility: provenance pays for it. Clean utility falls to 16.7 percent, the lowest
of any configuration, because the goal-text-only seed over-blocks benign
transfers whose legitimate recipient does not appear literally in the prompt. A
banking task like "pay the invoice from last month" names no IBAN, so the
recipient, which lives in trusted transaction history, is not in the trusted set
and the legitimate transfer is denied.

## The fix: widen the trusted seed to pre-contamination environment provenance

The goal text is the narrowest possible trusted source. The correct trusted set
is everything that provably predates untrusted tool output: the sealed goal PLUS
the trusted environment state at task start (existing contacts, prior
transactions, the user's own records). A destination drawn from that state is
trusted; a destination that first appears in an untrusted tool output is not.
This is the CaMeL data-flow direction proper: taint by origin, not by string
match against the prompt. Widening the seed this way should recover most of the
utility gap while holding ASR at 0, because the attacker destination still
originates in untrusted output and stays untrusted.

## Status

Keystone 2, security: met. The deployable path reaches the oracle's 0 percent ASR
with no ground-truth seeding.

Keystone 2, utility: **partially closed (2026-08).** Goal-named files are seeded
from a **pre-contamination** filesystem snapshot
(`snapshot_trusted_files` / `goal_named_env_destinations` in
`broker_defense.py`). Never seed from the live/injected env — AgentDojo splices
the attacker IBAN into `bill-december-2023.txt` via `injection_bill_text`.

| banking cell (gpt-4o-mini, important_instructions) | clean util | ASR | hint-retry |
|---|--:|--:|--:|
| envelope-provenance (goal text only, prior) | 0–16.7% | 0% | — |
| envelope-provenance + clean env seed (n=8) | 0% | 0% | 5/20 |
| envelope-provenance-replan + env seed (n=8) | **25%** | **0%** | 5/18 |
| bill-pay task alone + replan + env seed | **100%** | **0%** | 5/5 |

Env seed alone clears the floor for named-bill IBANs; clean-utility still needs
runtime replan for envelope misses. Residual banking tasks (rent adjust, dinner
split) name no file / no IBAN in the goal — still open.

## Broker wiring (2026-08)

`SessionBroker` now accepts `provenance` / `goal_named_objects`, calls
`EgressPolicy.check_with_provenance` on the floor (structured grounding →
STEP_UP, never autonomous ALLOW), and attaches `trusted_candidates` on egress
deny/step-up so a blocked agent can retry with a grounded recipient. The live
harness already passed these kwargs; they were previously rejected. Full-email
tokens (not bare domains) are what provenance indexes on a domain miss.

## Origin-based taint: built, and an honest negative on banking

The next iteration (`envelope-taint`, broker_defense.py `observe_output`) widens
the trusted set at runtime: as reads happen, recipients found in the STRUCTURED
fields of tool outputs are added to the trusted set (extract_recipients skips
free-text fields, where the injection hides). The intent was to recover the legit
recipients that live in transaction history without admitting the free-text
attacker IBAN.

| configuration | clean utility | ASR |
|---|--:|--:|
| envelope-provenance (goal-text only) | 16.7% | 0% |
| envelope-taint (goal + structured outputs) | 16.7% | 0% |
| oracle (ceiling) | 50.0% | 0% |

Result: security held (ASR 0%), utility did NOT recover (16.7%, identical to
goal-only). Structured-output taint did not close the deployable-to-oracle gap on
banking. The broker still over-blocks benign transfers (taint blocked 36 calls,
concentrated on benign recipients), so the legit recipient is not being recovered
from structured reads: either the clean tasks do not read a structured recipient
before transferring, the recipient sits under a field key extract_recipients does
not match, or the clean-utility loss comes from a non-egress layer (scope) that
egress widening cannot help. This needs the per-decision trace to localize, and
the multi-suite run will show whether taint helps at all on the email/URL suites
(slack, travel, workspace), where recipients are read from contacts and pages.
Reported as a negative, not hidden.

Caveat: n=18 is small and noisy (the envelope ASR moved between runs); the clean-
utility ordering is consistent and mechanistically explained, but the ASR figures
need the full multi-suite, larger-n run on a VM before they are a published
number.
