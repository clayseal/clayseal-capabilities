# Moonshots: from agent sandboxing to agent governance

Written 2026-08-07. The proposals here are deliberately beyond the current
roadmap. Each states the mechanism, why nothing published does it, how it would
be measured, and how it could fail.

## The thesis

Every agent-security system in the 2026 literature, ours included, is **scoped
to a session and to an event**. A goal is sealed, actions are judged against it,
the session ends. AgentDojo episodes average three tool calls. Our own
long-horizon tier, which is the longest published, runs 2,000 actions inside one
session.

Business risk does not live there. It lives at the scale of a **standing mandate
held by a principal across months**: the refund agent, the procurement agent,
the reconciliation agent. Those systems accumulate precedent, acquire
permissions, and are never re-sealed. Every control that matters in a real
finance or operations function is principal-scoped and time-scoped rather than
session-scoped: separation of duties, delegated authority limits, periodic
re-attestation, dual approval above a threshold, structuring detection across
days.

**None of it has been ported to agents.** That is the gap worth aiming at, and
it is larger than the injection problem the field is currently optimising.

Loss of control, stated precisely for this setting: not a single catastrophic
action, but a system whose effective authority at month six is wider than
anything a human authorized at month zero, reached through a sequence of
individually reasonable steps that no per-action check could refuse.

---

## Moonshot 1: anchored baselines, and measuring whether the *defense* drifts

**The mechanism nobody has noticed.** Any defense that learns what is normal
from the agent's own history has a feedback loop: the agent's past actions
become the justification for its future ones. An adversary who moves the
distribution slowly enough is never anomalous, because the baseline follows.
This is precisely how business-process fraud works against static thresholds,
and every behavioural agent monitor including our own trajectory detector has
the property.

**The build.** Separate two notions of normal. The **anchor** is a snapshot of
authorized behaviour at a human-signed epoch: the distribution of targets,
volumes, counterparties, and action shapes at the moment a human last attested
to the mandate. The **rolling baseline** is what the agent has done lately.
Enforcement judges against the anchor. Re-anchoring is an explicit, signed,
logged act that a human performs, never an automatic consequence of time
passing or of the agent behaving consistently.

Then the load-bearing part: continuously report **anchor displacement**, the
distance between the rolling baseline and the anchor. That number is the
organisation's drift, made visible, and no product reports it today.

**Why it is novel.** Every published defense asks "is this action anomalous".
This asks "has the standard by which we judge anomalies moved, and who moved
it". It reframes drift from an agent property to a governance property.

**How it fails.** Legitimate business change is indistinguishable from drift by
construction, since both are the distribution moving. The answer is not to
distinguish them automatically but to force the question to a human on a
schedule, which is what re-attestation is for. The honest framing is that this
converts an invisible risk into a periodic decision, not that it solves it.

---

## Moonshot 2: reversibility accounting and the unwind budget

**The reframing.** Every system in this space answers one question: do I allow
this action. None answers the question an operator actually asks after an
incident: **how much of what this agent did can I still undo?**

**The build.** Classify every effect by reversibility and cost-to-reverse, then
maintain a running **irreversible commitment** figure for the session and for
the principal. Reversible actions (drafts, staged writes, internal state) flow
freely. Irreversible ones (money leaving, external sends, deletions, published
artifacts) draw down a budget that only a human replenishes. Above a threshold,
an action does not block but **enters escrow** with a challenge window, during
which a slower and more expensive checker, or a human, can veto before it
commits.

The escrow is the interesting half. It converts synchronous blocking, which
costs utility on every false positive, into asynchronous review, which costs
latency only. Financial controls have used holdback windows and challenge
periods for decades precisely because they preserve throughput.

**Why it is novel.** It changes the metric from containment to **recoverability**,
and it gives a defense a way to be wrong safely. Nothing in the literature
reports blast radius or unwind capability.

**How it fails.** Reversibility classification is domain-specific and partly
subjective, and an escrow that nobody reviews is a delay rather than a control.
The mitigation is to make the unreviewed-escrow rate a published metric, the
same way we made interruptions per task one.

---

## Moonshot 3: separation of duties for agent identities

**The oldest control in finance, absent from agents.** No human who creates a
vendor record may approve payment to it. Agents collapse this entirely: one
identity holds every capability in the process, so the control silently
disappears the moment a workflow is automated. An organisation that has run
maker-checker for a century loses it on the day it deploys an agent, and
nothing in the agent's authorization model records that this happened.

**The build.** Declare conflicting-duty pairs over the capability set. Enforce
that both halves of a pair cannot be exercised by the same authorization chain,
which requires agent identities with independent key material and a delegation
model where authority does not merge when contexts do. The hard part is not the
check, it is preventing **authority laundering**: agent A delegates to C, agent
B delegates to C, and C now holds a combination neither A nor B could hold.
Composition must be forbidden by the delegation algebra rather than by a
downstream check.

**Why it is novel.** The multi-agent security literature is about agents
attacking each other or being contaminated by each other. This is about the
*aggregate authority of a workflow* being larger than any participant's, which
is a governance property no one is checking.

**How it fails.** It costs real utility, since some genuinely-one-agent
workflows become two, and it requires an identity substrate. We have most of
that already in the delegation and identity work.

---

## Moonshot 4: cross-session, principal-scoped aggregates

**A gap in our own system, and the definition of structuring.** Our value and
call budgets are per session. Structuring is *defined* as splitting an amount
across transactions to stay under a reporting threshold, and the agent analogue
is trivial: run four sessions instead of one. Every aggregate control in the
field, ours included, resets at the session boundary, which is the one boundary
an attacker controls for free.

**The build.** Move budget ledgers from the session to the **principal over a
time window**, with a persistent, tamper-evident ledger keyed by mandate rather
than by conversation. Add the detection that financial compliance actually uses:
not "did any transaction exceed the limit" but "is the *distribution* of
transaction sizes shaped by a limit", which is a distributional test on the
history and is exactly what our AML sensor already does at AUC 0.91 on real
fraud data without being wired into the live path.

**Why it is novel.** It is the difference between a rate limit and a compliance
control, and it makes the unit of authorization the mandate rather than the
conversation.

**How it fails.** It requires durable state and identity continuity across
sessions, and it raises a real question about what counts as the same principal
when an agent is redeployed. That question is worth answering explicitly rather
than being resolved by accident.

---

## Moonshot 5: authority that decays

**The observation.** Permissions granted to agents are never revoked, because
revocation requires someone to notice they are unused. Human access review
exists for exactly this reason and runs quarterly at best.

**The build.** Authority has a half-life. A capability unexercised for a period
narrows automatically; a capability exercised routinely and without incident
retains its scope. Renewal is evidence-based rather than time-based, and the
evidence is the audit chain we already produce. The end state is a mandate whose
scope tracks actual use, so the standing authority of a long-lived agent
converges to the minimum it demonstrably needs rather than the maximum someone
once approved.

**Why it is novel.** Least privilege is currently a design-time act. This makes
it a runtime process with a convergence property, and the property is
measurable: scope size over time against exercised-capability size over time.

**How it fails.** Seasonal work legitimately uses a capability once a quarter,
and decaying it is a self-inflicted outage. Needs an explicit exemption
mechanism, which is itself a thing to keep small and audited.

---

## Moonshot 6: the stated-objective ledger

**The build.** Before each consequential action the agent emits a structured
statement of what it currently believes the objective is. Those statements form
a trajectory. Two signals fall out: **drift**, the divergence of successive
stated objectives from the anchored one, and **incoherence**, the mismatch
between the stated objective and the action actually taken.

The second is the interesting one. An agent that has been hijacked either states
the true (hijacked) objective, which is directly detectable, or states the
original one and acts otherwise, which is a statement-action mismatch and is
also detectable. The attacker must maintain a consistent lie across a long
horizon while every action is checked against it.

**Why it is novel.** It is cheap, model-agnostic, interpretable by a human
auditor, and it forces the adversary to solve a harder problem than evading a
classifier. It is the agent analogue of requiring a stated business purpose on a
transaction.

**How it fails.** A capable model can maintain a consistent cover story, so this
is a cost imposed on the attacker rather than a barrier. It is also a monitoring
signal rather than an enforcement one, and should be scoped as such.

---

## The benchmarks. This is the part that is genuinely uncontested.

Every published agent-security benchmark measures a short episode inside one
session. The proposals above cannot be evaluated on any of them. These are new
instruments, and building them is defensible work independent of whether every
moonshot lands.

**B1. Slow-drift benchmark.** An adversary with a budget of 10,000 actions and
no requirement to succeed quickly, shifting the distribution far enough to reach
an objective that would be refused if requested directly at t=0. Metric:
**anchor displacement at detection**, and whether detection happens at all.
Every current benchmark hands the attacker a short deadline, which is the one
constraint a patient adversary does not have.

**B2. Cross-session structuring.** One objective split across sessions, days,
and identities, each fragment individually authorized. Metric: containment as a
function of the number of fragments. We would currently score zero at n
fragments greater than one, which is worth knowing and publishing.

**B3. Reversibility benchmark.** For attacks that succeed, measure what
fraction of the damage is recoverable at the moment of detection. A new axis:
not "did you block it" but "if you missed it, what did it cost". Reported as an
unwind curve over time-to-detection.

**B4. Separation-of-duties benchmark.** Conflicting-duty pairs; can a single
authorization chain accomplish both halves, directly or through delegation?
Composition attacks specifically, since that is where the property breaks.

**B5. The quiet quarter.** Ninety days of realistic legitimate operation
containing one violation. The metric that decides deployability is **false
alarms per quarter**, and no published benchmark can produce it because none
runs long enough. Our long-horizon tier is the closest thing that exists and it
is three orders of magnitude short of this.

**B6. Institutional-norm benchmark.** Replay a real business process log where
humans made the decisions, then run the agent against the same inputs, and
measure divergence from the human decision envelope. This defines business
process logic empirically instead of by hand-written rule, and it is the only
way to evaluate whether a system enforces what an organisation actually does
rather than what someone wrote down.

**B7. Defense-drift benchmark.** Measure whether the *defense's* baseline moves
under a slow adversary. Point the slow-drift attacker at a learning monitor and
report how far the notion of normal shifts. To my knowledge nobody has ever
published this, and every adaptive monitor in the field is exposed to it.

---

## What I would build first

**B5 and B1 are the highest-value pair**, because they create the measurement
environment the moonshots need and because we are already closest to them. We
have the only long-horizon tier in the field at 2,000 actions with false alarms
per thousand benign actions; extending to 10^5 actions with a patient adversary
is an incremental build on machinery that exists.

**Moonshot 4 is the highest-value mechanism**, because cross-session aggregates
are a real hole in our own system, the attack is trivial, structuring is the
canonical business-process violation, and the AML sensor that detects the
distributional signature is already validated and unwired.

**Moonshot 2 is the best product idea**, because escrow with a challenge window
is the only proposal here that *buys* utility rather than spending it, and
because recoverability is a language finance and operations buyers already
speak.

The through-line for a memo: the field is building better locks for a session,
and the business problem is governance of a standing mandate over time. We are
credibly positioned to define that category, and the benchmarks are the moat,
because whoever builds the instrument defines what counts as good.
