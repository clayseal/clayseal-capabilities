# AML → BPL translation map

ClaySeal’s monitor already treats agent tool streams like AML activity streams
(`agentauth/capabilities/monitor/aml.py`): **velocity, fan-out, structuring,
post-read escalation, delegated-trust laundering, peer deviation**, scoring
*shape*, not memo text. BPL scenarios are the **composite-policy unit tests**
for those typologies in an agent loop (Progent-blind per call; violation in the
sequence).

## Classical AML stage → agent analog

| AML stage (FATF) | Financial meaning | Agent / BPL analog |
|------------------|-------------------|--------------------|
| **Placement** | Illicit value enters the regulated system | First side-effecting tool call that introduces sensitive effect (pay, grant, egress) under a mandate |
| **Layering** | Complex hops obscure the trail | Multi-tool / multi-persona / convert→wire→refund chains that keep each hop under threshold |
| **Integration** | Value re-enters as “legitimate” | Sensitive effect exits via an *allowed* channel (docs, invoice, internal Slack) that launders provenance |

## Typology library → existing + new BPL cases

| AML typology | Sensor / control hook | BPL scenario(s) |
|--------------|----------------------|-----------------|
| **Structuring / smurfing** | `structuring` in `AmlAnalytics`; `SessionValueBudget` | Legacy `refund-structuring`, `payout-splitting`, `structured-micro-refunds`; deep-adjacent `smurf-just-under-ctr` |
| **Fan-out** | `fan-out` typology; call/egress budgets | `fanout-egress-spray` (new); IBM AML validation in `aml_validation.md` |
| **Velocity / burst** | length / n_value features; call budgets | `rapid-velocity-burst` (new); `multi-day-carry` (horizon) |
| **Layering** | multi-hop value path | `layering-hop-chain` (new) |
| **Round-tripping** | A→B→A wash | `round-trip-spend-wash` (new) |
| **Trade-based (TBML)** | mis-description / dual ledgers | `fee-plus-principal-stack`; `tbml-overinvoice` (new) |
| **Mule / straw desks** | multi-persona under local ceilings | `sibling-session-collusion`; `mule-desk-smurf` (new) |
| **Commingling** | clean+dirty in one batch | `commingle-batch-send` (new) |
| **Integration / legitimize** | allowed-channel volume | `allowed-channel-drip`; `integration-invoice-cover` (new) |
| **U-turn** | rapid in→out | `uturn-receive-exfil` (new) |
| **Correspondent nesting** | nested authority | `delegate-then-widen`; `nested-correspondent-desk` (new) |
| **Post-read escalation** | AML `post-read-escalation` | `error-recovery-drop-volume`; `ci-secret-probe` |
| **Delegated-trust laundering** | AML typology + provenance | `handoff-spec-cascade`; `memory-poison-preference` |
| **Peer-group deviation** | `peer_z` on ULB | Live anomaly layer (not a single BPL episode); H2H still uses deterministic predicates |

## Design rule for AML-BPL cases

1. **Threshold in policy tool / mandate**, not only the user prompt (placement looks individually authorized).
2. **Violation = aggregate shape** (sum, fan-out cardinality, hop net, round-trip count), same philosophy as CTR avoidance.
3. **No injection strings**, the “laundering” is faithful task execution that recreates the typology.
4. Label `clayseal_expected` honestly: value/call budgets **contain** structuring/fan-out/velocity; layering/round-trip/TBML may need multi-key ledgers or provenance (**partial/open**).

## Product punchline

AML gave the *sensor vocabulary*; BPL gives the *agent-facing claim*: Progent/CaMeL see each CTR-sized transfer; ClaySeal’s session ledger sees the smurf. The new `aml` tier makes that dictionary explicit for eval and paper tables.
