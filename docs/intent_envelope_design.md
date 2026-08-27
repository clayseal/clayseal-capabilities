# The intent envelope

When a session starts, Clay Seal turns the stated goal into a set of checks it
can apply to every later action: which tools that goal implies, in what order,
against what targets, how many times. That set is the intent envelope. This
document explains how it is derived and why it is built from the goal alone,
never from what the agent has done since.

## Thesis

The behavioral layer should judge each action against **the sealed task**, not
against a population of past runs. A goal-derived envelope needs no warm-up, is
robust on short runs, and is injection-resistant because it is compiled once from
the trusted prompt. The learned, population-based detector we already built is
not discarded: it is demoted to a *sensor* inside a runtime-assurance
architecture whose safety comes from the verified, goal-derived envelope.

This reframing is not novel to us. It is the standard of the two most
safety-critical industries: self-driving and aviation both build a **declared,
verifiable envelope** and monitor conformance to it, rather than learning
"normal" from history. Anti-money-laundering does the same at onboarding.

## 1. The reframing: specification, not anomaly

Two questions a monitor can ask about an action:

- **Does this action serve the stated task?** Judged against the goal. No history.
- **Is this action unusual versus how the task normally goes?** Judged against a
  population. Needs history, so it has a warm-up problem.

The intrusion-detection literature settled this trade decades ago.
[Specification-based detection](https://www.seclab.cs.sunysb.edu/seclab/pubs/ccs02.pdf)
crafts the correct behavior of an object as a spec (a finite-state machine) and
flags deviations. It catches novel attacks **with a low false-alarm rate**,
exactly the opposite of anomaly detection, which detects the unknown only at the
price of high false alarms. We built the anomaly side (frequency model, learned
corridor, peer-group stats) and inherited its warm-up cost. The memo asks for the
specification side.

## 2. The Waymo analogy, done right

The memo's own analogy is self-driving. Read properly, it argues against learning
the corridor from history.

**Responsibility-Sensitive Safety (RSS, Mobileye).** RSS is a provable minimum
safety envelope: a set of logically provable rules and prescribed responses,
formalized as transparent mathematical constraints. It **operates as a separate
layer from the AI decision-maker** and **independently of learned systems**. RSS
does not estimate "normal driving" from a corpus. It derives the safe set from
the goal and the physics and right-of-way of the domain. This is the industrial
existence proof for a history-free safety envelope.

**Operational Design Domain (ODD).** The pre-declared conditions under which the
system may operate at all (roads, weather, speeds, a geofence). Outside the ODD
the system does not operate. The agent ODD is the task's declared scope: which
tools, resources, paths, and domains are in play.

**Simplex / Runtime Assurance.** A high-performance but unverified controller is
wrapped by a simple, verified safety monitor with a certified fallback; when the
trajectory approaches the unsafe boundary, control switches to the safety
controller. This is the architecture for the whole system:

| Simplex role | Clay Seal component |
|---|---|
| High-performance unverified controller | the LLM agent |
| Verified safety envelope (RSS) | the **goal-derived intent envelope** |
| Operating envelope (ODD) | the task scope (tools/resources/paths/egress) |
| Runtime monitor + override | the `SessionBroker` + enforcement floor |
| Certified fallback (minimal-risk condition) | step-up / halt / revert |
| Monitor's sensor (with characterized FP/FN/latency) | the learned statistical detector |

The decisive consequence: **safety comes from the verified envelope, not from the
sensor.** A modern runtime-assurance monitor is characterized by its sensor's
false-positive, false-negative, and latency distributions, and safety still holds
because the verified backup is the backstop. So the warm-up problem is not a
safety problem. With zero history the RSS-like envelope and the floor give the
guarantee; the learned sensor only adds sensitivity once warmed up.

## 3. Cross-domain synthesis

Every high-stakes field that must judge behavior against intent uses a declared
envelope plus conformance, not learned normality.

| Field | Mechanism | What it contributes to the design |
|---|---|---|
| Self-driving (RSS) | provable safe set, separate from the learner | history-free envelope; the safety layer is not the AI |
| Self-driving (Simplex/RTA) | verified monitor wraps unverified controller | the doer/checker architecture; fallback |
| Aviation | filed flight plan + envelope protection + RNP corridor | the plan is filed per-flight (per-task), not learned; a corridor of allowed deviation |
| Security (CFI) | pre-compute the legitimate control-flow graph; enforce the trace stays on it | derive the action-flow graph from the task; off-graph action is an attack |
| Security (spec-based IDS) | FSM of correct behavior; flag violations | novel attacks at low false alarm |
| LLM agents (TaskShield, AgentSpec) | check each tool call against the stated goal | the emerging frontier; but most read content (injectable) |
| Intent-to-execution integrity | four integrity properties; "judgment integrity" is the open problem | names our exact gap; our answer avoids reading untrusted content |
| AI planning (HTN, PDDL) | decompose the goal into subtasks and primitive actions with preconditions/effects | the envelope *generator* |
| Planning (landmarks) | facts/actions that must occur in any plan | "any legitimate trace must include these" |
| Process mining (conformance) | align a trace to a process model; graded fitness; typed deviations | the *comparison* mechanism, graded not binary |
| Control theory (MPC safety filter) | admit an action only if a safe completion still exists | graceful re-planning; "is the goal still reachable through this action?" |
| Finance (KYC / AML) | expected-activity profile declared at onboarding; flag deviation | declared, not learned, expected behavior in a high-stakes domain |
| Immunology (two-signal) | a cell activates only on antigen **and** danger co-stimulation | flag only actions that are off-plan **and** consequential; controls false alarms |
| Immunology (danger model) | respond to damage, not mere non-self | judge by consequence, not mere unusualness |
| Developmental biology (Waddington) | canalized valleys are the plausible developmental paths | the envelope as a landscape of valleys around the goal |
| Cognitive science (scripts/frames) | tasks invoke declarative scripts (restaurant: order, eat, pay) | task templates as a generation source |
| Physics (least action) | systems follow extremal paths | large deviation from the goal-directed path is notable |
| Law/finance (mandate, IPS) | a power-of-attorney / investment mandate declares authorized acts and limits | the envelope is a signed mandate; deviation is a breach |
| Star Trek | mission profile + command authorization codes + safety protocols | declared mission profile; step-up codes for consequential acts |

The convergence is total: **declare the expected envelope from the goal, monitor
conformance, escalate on deviation, keep a verified fallback.**

## 4. The three sub-problems

### 4a. Representation: what is the envelope?

A **typed, parameterized plan-graph**, the union of the flight plan, the CFG, and
the process model:

- Nodes are action classes (tool + verb + resource-class), the vocabulary we
  already tokenize.
- Edges are a partial order of expected phases (a task like reconcile-invoices is
  list, then read-many, then match, then pay-some), an HTN decomposition
  flattened to an action DAG.
- Nodes carry **preconditions and effects** from a lightweight tool ontology
  (what a tool reads, writes, sends, and whether it is reversible or
  consequential).
- Nodes carry **parameter bindings** to the goal (the payees, amounts, paths,
  and domains the goal authorized).
- The whole is a **superset** (permissive): it circumscribes the plausible, not a
  single golden path.

### 4b. Generation: goal to envelope, once, on trusted input

The envelope is compiled at seal time by the control plane, the same step that
already builds the authority envelope. Sources in increasing richness:

1. **Structured intent** the control plane already emits (we have this today).
2. **Task-template / HTN-method library**: retrieve the decomposition for this
   task kind (the script). Reuses the retrieval stack already in the codebase.
3. **A planner** (symbolic PDDL/HTN, or an LLM) run **once on the trusted, sealed
   prompt** to emit the expected action DAG.

The planner point matters and is not the injectable judge we removed. That judge
read untrusted tool **outputs** on every action. The generator reads only the
**trusted sealed prompt at t=0**, before any contamination, and emits a
structure that is then **signed as control-plane data**, like the mandate. Its
output is verified and immutable at runtime; nothing the agent later reads can
change it. This is exactly RSS as a separate layer from the decision-maker.

### 4c. Conformance: trace versus envelope, online, graded

Borrow [process-mining conformance checking](https://www.processmaker.com/blog/what-is-conformance-checking/).
For each action, alignment / token-replay against the plan-graph yields a graded
fitness and typed deviations:

- **off-plan**: no node the action maps to (behavior in the trace not in the model).
- **out-of-order**: a node reached before its predecessors.
- **out-of-parameter**: right tool, wrong bound value (a payee the goal never named).
- **no-feasible-completion**: the MPC test, after this action, is a valid path to
  the goal still possible? If not, the action steered off-mission.
- **missing landmark**: a required step skipped (behavior in the model not the trace).

### 4d. False-alarm control: the immune two-signal rule

A deviation escalates only when it is **also consequential**. An off-plan read is
logged or escalated; an off-plan send, transfer, delete, or security-surface
write is blocked or stepped-up. This is T-cell co-stimulation (antigen plus
danger) and the danger model (respond to damage, not mere non-self). It keeps the
permissive-superset envelope from generating friction on benign exploration.

## 5. The recommended architecture

Name it **Agent Control-Flow Integrity**, or the **Intent Envelope**. Layered as a
Simplex runtime-assurance stack:

```
sealed goal ──(control plane, once, trusted)──▶ signed Intent Envelope
                                                   │
agent proposes action ─▶ SessionBroker ───────────┤
                          │  1. enforcement floor (hard: scope, protected zones,
                          │     egress, budgets, payload binding)      ← ODD + RSS-hard
                          │  2. envelope conformance (graded deviation) ← RSS-soft
                          │  3. two-signal gate (deviation × consequence)
                          │  4. statistical sensor (AML / drift / n-gram)  ← optional sensor
                          ▼
                    allow / step-up / deny  ──▶ tamper-evident decision receipt
```

- **Primary behavioral tier: envelope conformance** (history-free, from the
  signed goal). This is the RSS layer and the memo's per-task envelope.
- **Enforcement floor** stays the hard, per-action gate (the ODD and the
  provable-hard part of RSS).
- **Statistical detector demoted to a sensor** for what the plan-graph cannot
  express: aggregate abuse (structuring across many individually-valid payments),
  slow drift (CUSUM), peer-group weirdness. These genuinely benefit from history,
  and their imperfection cannot compromise safety because the verified envelope
  and floor are the backstop.

### Mapping to what we already have

| Design element | Existing component to reuse or refit |
|---|---|
| Envelope conformance monitor | `reachability.PathEnvelope`, refit to consume a **goal-derived** graph instead of a learned corridor |
| ODD / hard floor | `hardening/*`, `task_scope`, budgets, commit-token binding |
| Two-signal gate | `provenance.TaintTracker` (consequential) + a consequence classifier |
| Feasibility / re-planning | new, small: reachability over the plan-graph |
| Statistical sensor | `aml.py`, `drift.py`, `scoring/*` (kept, demoted) |
| Signed envelope | mint and sign like a mandate (`core.mandate`) |
| Runtime gateway + fallback | `broker.SessionBroker` (already the Simplex monitor) |
| Audit | `decision_log` receipts |

Most of this is refit, not new. The learned corridor code becomes the conformance
engine; it just reads a compiled graph rather than fitting one from data.

## 6. Why this fixes the warm-up problem

- **New task type**: gets a full envelope immediately from its plan. No history.
- **Short run**: conformance is a membership and progress check, not a statistical
  test, so one or two steps are judged fine.
- **Cold start is safe by construction**: even with zero history the envelope plus
  floor give the guarantee (RSS is history-free); the learned sensor only sharpens
  detection later.

## 7. Positioning versus prior art

The frontier ([TaskShield](https://arxiv.org/pdf/2505.03574), AgentSpec,
[intent-to-execution integrity](https://arxiv.org/html/2605.16976), CaMeL,
Progent) converges on "check the action against the goal." Most implementations
either read untrusted content with a larger model (injectable, the judgment-
integrity problem the survey calls open and impractical) or hand-write DSL rules
per app. Clay Seal's distinctive position:

- **Structural, not semantic**: conformance to a signed plan-graph over action
  metadata. It never reads untrusted content, so it cannot be prompt-injected. It
  answers the "judgment integrity" open problem structurally.
- **Compiled from the goal, signed, history-free**: an RSS-style separate layer.
- **Composed with a hard floor and tamper-evident receipts**: the Simplex fallback
  and the audit trail, which the guardrail papers lack.
- **The statistical layer as a characterized sensor**, not the safety mechanism.

## 8. Open questions and honest risks

- **Generation fidelity.** Compiling a faithful plan from an ambiguous natural-
  language goal is the hard part. Mitigations: the envelope is a permissive
  superset, deviations escalate rather than hard-block, and the feasibility test
  allows legitimate re-planning. The floor is the backstop when the envelope is
  wrong.
- **Tool ontology.** Preconditions, effects, and consequence per tool must come
  from somewhere: MCP tool schemas, a consequence classifier, or author
  declarations. Without it, conformance degrades to tool/verb/resource-class
  membership (still useful, weaker).
- **Trust of the generator.** If an LLM plans, it must run at t=0 on the sealed
  prompt and its output must be signed. Any per-action, content-reading planning
  reintroduces the injectable judge and is forbidden.
- **Parameter binding and re-planning within scope.** The envelope must permit the
  agent to legitimately choose among authorized resources without re-derivation.
- **What we deliberately give up.** Purely semantic subversion that stays on-plan,
  on-parameter, and non-consequential is not caught structurally. We accept this
  as the price of injection resistance, and lean on the floor, budgets, and the
  statistical sensor for aggregate cases.

## 9. Phased implementation

- **Phase A (history-free core).** Envelope schema; generate it from the
  `structured_intent` we already have; refit `PathEnvelope` as a conformance
  monitor over the goal-derived graph; two-signal gate via taint plus a
  consequence classifier; demote the statistical tiers to sensors. This alone
  removes the warm-up problem for the primary tier.
- **Phase B (richer envelope).** Tool ontology with preconditions/effects; the
  feasibility (MPC) test; landmark checks; sign the envelope like a mandate.
- **Phase C (generation).** Task-template/HTN-method library via the retrieval
  stack; optional planner-based generation on the sealed prompt, signed.

## Sources

- Specification vs anomaly detection: Sekar et al., *Specification-based Anomaly
  Detection*, CCS 2002.
- RSS: Mobileye/Intel *Responsibility-Sensitive Safety* fact sheet and
  formalization work; μODD extensions.
- Simplex / Runtime Assurance: Sha, *Using Simplicity to Control Complexity*;
  RTA safety-filter surveys.
- CFI: Abadi et al., *Control-Flow Integrity*, CCS 2005.
- HTN planning: SHOP2 and the HTN literature.
- Process mining conformance: alignment and token-replay techniques.
- MPC safety filters and control barrier functions.
- LLM-agent guardrails: LlamaFirewall, TaskShield, AgentSpec, TrustAgent,
  intent-to-execution integrity, CaMeL, Progent.
- AML/KYC expected-activity profiles.
- Immunology: the two-signal and danger models.
