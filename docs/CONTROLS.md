# What this produces evidence for, and what it does not

STATUS: current

The person who signs off on an agent deployment is usually a risk function
rather than an engineer, and they ask a different question: which of our
obligations does this help with, and how would an auditor see it.

## What this document is not

**It does not make anyone compliant with anything.** A library is not a control
regime. Compliance is a property of an organisation's processes, and the most a
component can do is produce evidence a control owner can point at. A vendor page
claiming "SOC 2 compliant" for a package is claiming something a package cannot
be, and this is not that page.

**It maps only where the mapping is exact.** Where a framework's text is quoted
below it is quoted verbatim from the source, linked at the end. Where only the
function or criterion family can be supported, that is the level it is stated
at, rather than inventing a subcategory identifier that reads authoritative and
is not checkable.

## EU AI Act

The two articles this touches directly, and the mechanism that touches them.

**Article 12, Record-Keeping.** "High-risk AI systems shall technically allow for
the automatic recording of events (logs) over the lifetime of the system", and
those logs must support traceability for "identifying risk situations",
post-market monitoring, and operational monitoring by deployers.

`DecisionLog` records every authorization decision, not only the refusals: the
tool, the verb, the resource, a hash of the arguments, the outcome, the layer
that decided and the reasons. Records are hash-chained, so a missing or altered
one is detectable rather than merely absent, and `verify()` returns which record
broke. `traceparent` on each record is the join to the caller's own trace, which
is what makes "reconstruct this decision" a query rather than an archaeology
project. `OcsfSink` puts the same event where post-market monitoring already
looks.

What it does **not** give you: the article is about the AI system over its
lifetime, and this logs one boundary of it. A deployment still needs records of
the model, the prompts, and the data. This is one input to Article 12 and not a
discharge of it.

**Article 14, Human Oversight.** High-risk systems must be built so they "can be
effectively overseen by natural persons", with mechanisms to monitor, intervene
and deactivate.

The step-up path is the intervention mechanism: an action that needs a person
halts and produces a signed request carrying what was attempted and why, and
`resolve_step_up` is the only thing that releases it. `Guardrail` raises
`StepUpRequired` separately from `Refused` for exactly this reason, because a
caller that collapses them has removed the oversight point while appearing to
keep it. Deactivation is the grant expiring or the policy being replaced, both
of which are control-plane actions rather than agent-reachable ones.

What it does **not** give you: oversight requires a trained person who
understands the system, which is a staffing and process obligation. The library
can make the intervention point exist and cannot make anyone competent to use
it.

## NIST AI RMF

Stated at the function level, because that is the level the public text
supports without guessing at subcategory identifiers.

**MEASURE**, specifically MEASURE 2.7, Security and Resilience. The benchmark
tree is the evidence: containment measured against a cost column on every arm,
property fuzzing over 200,000 generated inputs on both path readings, fault
injection across 26 component seams, and a null-before-power calibration on the
behavioural baseline. Every published number carries the command that produced
it, and three ratchets refuse to let the debt grow.

**MANAGE.** The floor, the budgets and the conditional withdrawals are the
treatment: a measured risk becomes a written grant, and the grant is enforced at
the boundary rather than by asking the model to behave.

**GOVERN.** The policy document is the artefact a governance function can own.
It is reviewable YAML, it is diffed in a pull request, `clayseal policy lint`
gates a merge, and `Policy.digest()` puts the hash of the exact document on
every decision, so an audit trail says which authority produced a decision and
not only what the decision was.

**MAP** is the one this contributes least to. Deciding what the system is for
and where it can do harm is done before a policy is written, and this consumes
that decision rather than informing it.

## OWASP Top 10 for Agentic Applications (2026)

The list a security reviewer is most likely to arrive holding, and the one whose
categories map closest to what this actually does. Stated per category, with the
ones it does not address kept in the table rather than dropped from it.

| | category | what this contributes |
| --- | --- | --- |
| **ASI01** | Agent Goal Hijack | **Direct.** The goal is sealed at session start and nothing the agent reads afterwards widens it. A destination that first appears in a document the agent read is not the same as one the goal named, and the provenance layer keeps them apart. Measured on AgentDojo `important_instructions`: 1 attack success in 216 runs. |
| **ASI02** | Tool Misuse & Exploitation | **Direct.** The grant enumerates tools, the proxy withholds the rest from the catalogue, and budgets hold the running total that catches a chain of individually permitted calls. This is the category the 132-scenario suite is about. |
| **ASI03** | Identity & Privilege Abuse | **Partial.** Commit tokens bind a decision to the exact arguments it was made about, the replay store spends each one once, and the principal ledger binds an aggregate limit to the mandate rather than the session. It consumes verified claims from your IdP and issues none: authentication is out of scope. |
| **ASI04** | Agentic Supply Chain | **Partial.** `policy init` treats a server's own tool catalogue as a claim rather than an authority: an effect may be raised and never lowered, and a server calling its effectful tool read-only is reported. It does not verify the provenance of the server, the model, or a dependency. |
| **ASI05** | Unexpected Code Execution | **Partial, and only at the syscall tier.** The tool-call layers see no call for a DNS tunnel to make, so they deny nothing; the sandbox backend compiles the same envelope into a syscall policy and denies all four queries on the captured trace. The reference backend is macOS only. |
| **ASI06** | Memory & Context Poisoning | **Not addressed.** Poisoned context is an input to the agent, and this layer reads the agent's actions rather than its memory. It bounds what a poisoned agent can do; it does not detect the poisoning. |
| **ASI07** | Insecure Inter-Agent Communication | **Not addressed here.** Delegation carries a scope that can only narrow, which bounds what a sub-agent inherits. The transport between agents is a separate distribution's problem. |
| **ASI08** | Cascading Failures | **Not addressed.** A per-session authority bound says nothing about propagation across an ecosystem of agents. |
| **ASI09** | Human-Agent Trust Exploitation | **Not addressed, and worth naming as a cost.** Step-up puts a person in the loop and a person approving without reading is the failure mode this category describes. The gateway can make the intervention point exist and cannot make anyone competent to use it. |
| **ASI10** | Rogue Agents | **Weakly.** The behavioural layer watches the shape of a session against its goal, and it is advisory rather than blocking. On the corpora where harm is defined by the content of an authorized action rather than by a binding the gateway holds, the shipped detector is at chance. Do not buy this layer. |

Read the column, not the count. Four rows say "not addressed", and the two
categories this is strongest on are the two that are about **authority**, which
is what an authorization layer is for.

## SOC 2

At the criterion-family level.

**CC6, Logical and Physical Access.** An agent is a principal, its grant is the
access control, and the enforcement is out of process when it runs behind
`clayseal proxy` or `clayseal serve`, so it does not depend on the agent
cooperating. The principal ledger binds aggregate limits to the mandate rather
than to a session, which is what stops "open a second conversation" from being a
reset.

**CC7, System Operations.** Decisions reach a SIEM in a shape it already parses,
`unrecorded_decisions` counts anything the evidence plane could not account for,
and the behavioural baseline turns "has this agent changed since we approved it"
into a test with a measured false-alarm rate rather than a dashboard.

## The honest boundary, in one paragraph

This is an authorization layer. It binds what an agent may do, records what it
decided, and asks a person when the grant is ambiguous. It does not evaluate the
model, it does not test for bias, it does not manage training data, and it does
not know whether the task was a good idea. Roughly a quarter of the rules in a
real business policy are not about authority at all and this layer should not
pretend to hold them: `benchmarks/results/external_policy_documents_coverage.md`
measures that at 23%, on documents nobody here wrote.

## Sources

- EU AI Act Article 12, Record-Keeping: https://artificialintelligenceact.eu/article/12/
- EU AI Act Article 14, Human Oversight: https://artificialintelligenceact.eu/article/14/
- NIST AI RMF 1.0 (AI 100-1): https://nvlpubs.nist.gov/nistpubs/ai/nist.ai.100-1.pdf
- OWASP Top 10 for Agentic Applications 2026: https://genai.owasp.org/initiatives/agentic-security-initiative/
