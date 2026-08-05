# Improvements: where the performance gap actually is

Derived from our own measurements plus the 2026 literature. Ordered by expected
value, not by ease. Each item states the evidence, the mechanism, and the
measurement that would prove it worked.

The headline: **our security is done and our utility is not.** Across every live
result we hold ASR at 0%, matching or beating every published defense. We pay
for it with a utility cost far above the state of the art. CaMeL reports 77% task
completion against an 84% undefended baseline, a 7-point cost. Our deployable
provenance path reports 16.7% against a 50% baseline on banking, a 33-point cost
on a much lower base. That gap is the product problem, and it is where the
remaining work should go.

## 1. Provenance closure over trusted data flow (utility)

**Evidence.** [results/provenance.md](../benchmarks/results/provenance.md):
`envelope-provenance` hits 0% ASR, matching the oracle ceiling, at 16.7% clean
utility against the oracle's 50%. The doc names the cause: the trusted set is
seeded from goal *text only*, so a benign flow that fetches a recipient from the
user's own records is denied because the destination never appeared as a literal
in the prompt.

**Mechanism.** PAuth (Microsoft Research, arXiv 2603.17170) is the closest prior
art and the right shape: bind each operand to its *symbolic provenance* rather
than to a literal, so a value is authorized when it demonstrably derives from a
legitimate upstream computation of the same task. Our `taint` mode is a partial
version already, widening the trusted set from structured fields of tool
outputs. The full version closes provenance transitively: a destination is
trusted if it is reachable from the sealed goal through a chain of calls whose
own inputs were trusted, and untrusted the moment any link's input came from
free-text content that entered after the seal.

The distinction that makes it safe is the one `taint` already relies on:
injections live in free text, legitimate values live in structured fields. The
upgrade is to propagate that judgement across multiple hops instead of one.

**Measurement.** Clean utility at fixed 0% ASR, paired against `none` so only
defense-caused losses count, on the model ladder. Target: within 10 points of
the oracle ceiling, which would put us at CaMeL's cost level with a stronger
security result.

## 2. Report endorsement frequency as a first-class metric

**Evidence.** The adaptive-evaluation paper (arXiv 2606.26479) specifies four
standard metrics: action-level success, utility retention, **endorsement
frequency**, and monitor overhead. We publish the first, second, and fourth. We
collect step-up counts and do not report them.

**Why it matters more than it looks.** The same paper names approval fatigue as
an attack surface: a defense that reaches 0% ASR by asking the human to confirm
everything has moved the vulnerability rather than removed it, and a buyer with
an SOC understands that immediately. Our supervised-utility number is currently
flattering for exactly this reason, since every step-up counts as recoverable.

**Measurement.** Step-ups per task and per action, reported beside supervised
utility everywhere it appears. A supervised number without its endorsement rate
should be treated as incomplete.

## 3. Implicit flows and side channels

**Evidence.** Same paper, third named gap: information-flow systems that track
explicit dependencies miss covert channels through exceptions, timing, and
control-flow decisions. Our taint tracker propagates through explicit data
dependencies only.

**Concrete attack.** The agent cannot send the credential, but it can branch on
it: request `https://attacker/a` if the first character is 'a', `/b` if 'b'. No
tainted value ever reaches an argument. Every call is individually in scope. The
secret leaks one bit at a time through choice of destination.

**Mechanism.** Detection at the action layer is the wrong place, since each
action is legitimate. The signals that work are aggregate: request-count
anomalies against the task's expected shape, and destination entropy. Our
`SessionCallBudget` already catches the volume form of this, which is why
scenario 08 (bulk exfil over an allowed channel) works. The narrow-channel form
is not covered.

**Measurement.** A new adaptive objective that succeeds only when N bits leak
through choice-of-call, with containment reported separately from the
data-flow objectives.

## 4. Attack the trusted computing base

**Evidence.** The paper's first named gap, and it applies to us directly: every
system, ours included, assumes the sealed goal is trustworthy. Our provenance
seed *is* the goal text. A user pasting attacker-authored content into their own
prompt authorizes the attacker's destination by construction.

**Mechanism.** This is not fully solvable at this layer, and pretending
otherwise would be dishonest. What is available: distinguish user-typed from
user-pasted content where the client can tell, and treat goal-derived
destinations as a weaker grant than mandate-derived ones, so a pasted IBAN gets
a step-up rather than a silent allow.

**Measurement.** A `poisoned-goal` knowledge level in the adaptive harness. Our
containment there will drop, and publishing that is worth more than another
100%.

## 5. Long-trajectory evaluation

**Evidence.** AgentDojo's mean trajectory length is about 3, and the corpus
repeats heavily. Published critiques (arXiv 2602.03117, 2605.16282) call this
out as the main reason benchmark results fail to predict deployed behaviour.
Real agent sessions run hundreds of calls.

**Why we are well placed.** The arena's `11-poisoned-turn` scenario is already
this: 1,779 observed events, one buried exfil connect, caught, task still
completes. That is the needle-in-a-long-trajectory case almost nothing else
measures, and it is currently a demo rather than a benchmark.

**Measurement.** Promote it to a tier with per-trajectory detection rate and
false-alarm rate per thousand benign actions, which is the form an SOC actually
budgets against.

## 6. Action-level rather than task-binary scoring

**Evidence.** Our utility is a binary per task, so a task that completes 9 of 10
steps scores identically to one that does nothing. With n=8 per suite each task
is worth 12.5 points, which is most of why our numbers move so much between
runs.

**Mechanism.** Score completed sub-goals. Reduces variance without any change to
the defense, and makes the utility comparison against CaMeL like-for-like.

## Not worth doing

- **More surface-leaving corpora.** [coverage analysis](../benchmarks/results/rigor_pass.md)
  shows 82% of our pooled attack events already leave the granted surface and we
  contain ~100% of them. Another such corpus moves no number that means
  anything.
- **Chasing AgentHarm's ceiling.** 94% of it is in-surface, where authorization
  is structurally blind. That is an intent-classification problem and belongs to
  a different layer.

## Sources

- Adaptive Evaluation of Out-of-Band Defenses (arXiv 2606.26479) — the three
  gaps, the four metrics, and the finding that out-of-band defenses like ours
  hold up under adaptive attack while in-band defenses collapse to 90%+ ASR.
- PAuth (arXiv 2603.17170) — operand-level symbolic provenance.
- CaMeL (arXiv 2503.18813) — the 77% vs 84% utility bar.
- FIDES / Microsoft Research — confidentiality and integrity labels.
- AgentDyn (arXiv 2602.03117), safety-benchmark taxonomy (arXiv 2605.16282) —
  trajectory length and benchmark realism critiques.
