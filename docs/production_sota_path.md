# The path to SOTA-on-escapes and production readiness

## The reframe: SOTA-on-escapes IS the utility problem

We hold attack success near zero across four suites. So do the frontier systems.
The difference is what it costs. CaMeL reports 77 percent utility with provable
security. Progent reports attack success cut to about 1 percent at preserved
utility. We reach zero attack success but pay clean-utility to do it. On the
security-utility frontier we are Pareto-dominated: same security, less utility.
So we are not yet SOTA on escapes, and the reason is not security, it is
precision. Closing the utility gap and becoming SOTA on escapes are the same task.

Why the gap exists: their authority envelope is derived precisely from the trusted
query. CaMeL takes control flow from the trusted query and lets untrusted data
only fill values, enforced by an interpreter with per-value capabilities. Progent
compiles a precise symbolic policy over tool arguments. Ours is a tool set plus a
destination set from a one-shot planner: authority at the granularity of which
tools, not which calls with which arguments. A coarse envelope over-blocks the
benign variation a real agent shows, which is exactly the clean-utility loss the
diagnostic found once the read bug was removed.

## Three innovations to close it

### 1. Provenance by verbatim matching of opaque tokens (the key idea)

The read-then-send escape and the banking recipient utility loss are the same
underlying gap: we cannot tell a destination that came from the user's trusted
history from one that came from injected content. CaMeL solves this with a full
dataflow interpreter. We do not need one, because of a property specific to the
arguments that matter.

Exfiltration destinations are opaque tokens: an IBAN, an email, a URL, an account
id. A language model cannot paraphrase an IBAN and have it still be that IBAN. To
use a destination it must copy the token verbatim. So verbatim matching of a
call's destination argument against the strings seen in prior tool outputs is a
SOUND provenance signal for exactly the class where exfiltration lives. Tag every
string in a tool output by the trust of its field (a structured recipient field
of a trusted-source tool is trusted; a free-text field, or any field of an
untrusted source, is untrusted). Classify a call's destination by the tag of the
output it matches: trusted origin allows, untrusted origin denies, and a
destination that appears in no prior output is checked against the sealed goal.

This is lighter than CaMeL (no interpreter, no model in the enforcement path) yet
sound for the class that matters, because the soundness comes from the token being
uncopyable-except-verbatim, not from tracking every value. It is simultaneously
the security lever (untrusted-origin destinations are denied) and the utility
lever (trusted-origin recipients from a STRUCTURED field are allowed).

Measured boundary of this idea (do not overreach it). The provenance is sound only
when trust attaches to the SOURCE CHANNEL, i.e. a structured recipient field of a
trusted tool. It FAILS when the destination is FREE-TEXT in a resource that is
also an injection target. We tried trusting the free-text of goal-named resources
(the bill file the user asked to read). A deterministic check showed it trusts the
attacker destination, because the injection is placed inside that very file: the
legit recipient and the attacker IBAN sit side by side as free-text in one trusted
source, and no predicate can separate two tokens sharing a source. This is the
core hardness of prompt injection, and it is why CaMeL keeps untrusted content in
a quarantined model with no tool access rather than trying to extract from it.

So the corrected rule: STRUCTURED-field recipients are auto-trustable; a free-text
recipient is NOT, and its correct handling is a STEP_UP (Innovation 3), never
auto-trust. This narrows Innovation 1 to the value-flow case it is actually sound
for, and it moves the free-text-recipient utility recovery onto graduated
response, where a human confirms "send to this recipient from a document?" once.
The implicit-flow limit still holds on top: a laundered destination is not a move
the model can make for an opaque token, but a co-located injected token is.

### 2. Authority as a typed plan with provenance-typed slots

Replace the tool-set scope with a declarative plan: a partial order of call
templates, each argument slot typed by where it must come from (the sealed goal,
a trusted read, or free). The planner, reading only the trusted query, emits this
once, before contamination. The symbolic layer binds authority to the templates.
A benign call that matches a template shape and slot provenance is allowed with
precision; an injected call matches no template's provenance requirement and is
denied. This is CaMeL's control-flow-from-trusted-query expressed declaratively,
with no model in the decision path, and it recovers the effect-scope precision the
28-tool travel suite loses today because it constrains arguments, not just tools.

### 3. Graduated response with a bounded friction budget

Step-ups recover benign utility under supervision, but unbounded step-ups are
fatigue. Calibrate the step-up rate the way we calibrated the detector false-alarm
rate: bound the fraction of benign actions that step up to a friction budget, and
reserve step-ups for genuinely uncertain consequential effects while allowing the
confident-benign (in-plan and trusted-provenance). This turns utility from a
single number into an honest triple: autonomous success, supervised success, and
friction as confirmations per task. That triple is the correct metric for a
system meant to run with a human on the escalation path, and it makes the
security-utility-friction tradeoff explicit and tunable instead of hidden.

## Why the combined system is decisively SOTA, not incrementally

Innovations 1 and 2 give CaMeL and Progent level precision on single-shot escapes,
so we match them on the security-utility frontier. But CaMeL and Progent are
per-call and dataflow defenses; the research map found none of them enforce the
composite, aggregate, goal-conditional-trajectory class. We already do, and it
survived an adaptive attacker on homogeneous workloads. So the combined system
sits on the frontier for single-shot escapes AND covers a threat class the
frontier does not touch. That is a dominating position, not a tie.

## Production readiness: the honest checklist

1. Statistical rigor. n=24 with high variance is not a claim. Full benchmark,
   multiple seeds, reported confidence intervals; the escapes result must survive
   resampling, and single-cell deltas must stop being quoted.
2. The metric. Report the autonomous, supervised, friction triple everywhere.
   Autonomous completion is a lower bound on the value of a supervised system.
3. Provenance from real data, not the oracle. Innovation 1 is the deployable
   replacement for oracle destination seeding; validate that it reaches the oracle
   ceiling at high utility across suites.
4. Adaptive robustness on escapes. Extend the adaptive adversary from the detector
   to the plan-plus-taint path; report the residual.
5. Enforcement substrate. The syscall floor (iVisor) for unforgeable enforcement,
   and its trajectory capture for the benign corpus the detector still needs on
   thin suites.
6. Latency and cost. The planner is one trusted call per task, outside the
   enforcement boundary; the enforcement itself is symbolic and fast. Measure and
   state both.
7. Escalation UX. The human-in-the-loop for step-ups is a real product surface,
   not a footnote; the friction budget makes it designable.
8. External validation. Run against attack corpora we did not write, and put
   CaMeL and Progent on the same table under one adaptive protocol.

## Sequence

1. Provenance by output matching (Innovation 1). Highest leverage: closes the
   banking recipient utility loss and the read-then-send escape at once, and
   removes the oracle. Begin by tracing why the current structured extraction
   missed benign recipients, then generalize to trust-tagged output matching.
2. Typed plan-with-slots authority (Innovation 2). Recovers effect-scope precision
   on travel.
3. Calibrated graduated response and the friction triple (Innovation 3). The
   honest deployable metric.
4. Rigor, adaptive-escapes, external corpora, iVisor floor. The hardening that
   turns a defensible pilot into a production claim.

The single most important idea here is the first one: provenance is sound by
verbatim matching for opaque-token destinations, so we get dataflow-grade escape
security without a dataflow interpreter, and the same signal is what recovers the
utility. That is the wedge that makes escapes-SOTA reachable at deployable utility.
