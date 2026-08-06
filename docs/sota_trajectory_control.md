# Toward SOTA on trajectories, escapes, and loss of control

What to build next, why, and how each piece would be judged. Grounded in what
this session measured rather than in what sounds impressive, because the session
also produced two claims that did not survive contact with a validation run.

## The lesson that shapes all of it

`deferallow` looked like the strongest result we had: banking clean utility
16.7% to 50.0% at ASR 0.0%. Travel killed it, 5.6% to 27.8%. The argument behind
it was that the intent envelope's plan-conformance gate catches nothing the
binding floor missed. That is true on banking and false on travel.

The generalisable finding is not about that flag. It is that **plan conformance
and destination binding catch different attacks, and neither subsumes the
other.** Any layer we add from here should be justified by naming the class of
attack it catches that existing layers do not, and then measured on a suite
chosen because it could refute the claim.

## Where we actually are

| Property | Status |
| --- | --- |
| Target binding (path, resource, action) | done, 100% adaptive containment, monotone ladder |
| Destination binding (egress, provenance) | done, deployable, ASR 0% on banking |
| Aggregate limits (BPL, value/call budgets) | done, the only rung catching fragmented spend |
| Plan conformance (intent envelope) | done, and now shown to be independently load-bearing |
| Long-trajectory detection | measured: 100% needle at 0 false alarms/100k actions |
| **Trajectory-level intent drift** | **n-gram/transformer scorers exist, not integrated as a control** |
| **Escape at the syscall boundary** | **not built; symlink and TOCTOU are open by construction** |
| **Control-theoretic evaluation** | **not done; we have no safety/usefulness frontier** |

The three bold rows are the gap, and they map exactly onto your three questions.

---

## 1. Trajectories: adopt the AI-control framing, not just better detection

The 2026 control literature (Greenblatt et al.; *Evaluating Control Protocols
for Untrusted AI Agents*, arXiv 2511.02997) has converged on a framing we are
one step away from and would benefit disproportionately from adopting.

**What it is.** Stop asking "is this action authorized" and start asking "what
protocol keeps a *deliberately subverting* agent from causing harm, at what cost
to usefulness". A protocol is a policy over the whole trajectory: monitor with a
weaker trusted model, defer to trusted when suspicion is high, resample,
escalate to audit. Results are reported as a **safety/usefulness Pareto
frontier**, not a pair of numbers.

**Why it fits us unusually well.** Our layers already *are* control protocol
elements: the floor is a deterministic trusted monitor, step-up is defer-to-human,
budgets are an audit budget. What we lack is the frontier: we report single
operating points, so a buyer cannot see the shape of the tradeoff or choose
their own point on it. The `graduated` and `defer` flags are literally two
points on a curve we have never drawn.

**Concretely.**
- Sweep the step-up threshold and plot ASR against clean utility, per suite and
  model. We have all the machinery; this is a loop, not a new mechanism.
- Add an **audit budget**: the human can be asked at most N times per session.
  This is the resource the control literature treats as scarce and we currently
  treat as free, which is why our oracle path can post 84% supervised utility at
  0.72 endorsements per task and call it a win.
- Report **safety under an adaptive attacker**, per the same literature's
  finding that defer-to-trusted protocols look strong against naive attacks and
  degrade under real red teaming. Our adaptive harness already does this for the
  authorization layer; it does not yet cover the step-up policy, which is
  attackable by making benign-looking requests until the human stops reading.

**How it would be judged.** A frontier curve, plus the area under it, against
CaMeL and Progent at matched usefulness. That is a materially stronger artifact
than any single ASR number and it is the form the field is standardising on.

---

## 2. Loss of control and BPL: the aggregate is the signal

Loss of control is a **property of trajectories, not states** (arXiv 2606.20610,
which analysed 183k real transcripts and found 698 credible scheming incidents).
Our per-action floor is structurally blind to it, and our budget rung is the
only thing that is not.

That makes BPL the most under-exploited asset we have. It is also the thing
enterprise buyers already understand, because it is how financial controls
work: velocity limits, circuit breakers, holdback windows, dual approval for
material amounts or novel counterparties.

**What to build, in order.**

**a. Circuit breakers on rate and cumulative exposure.** We enforce ceilings.
We do not enforce *velocity*. An agent that normally reads 10 customer records
and suddenly reads 10,000 is the canonical case, and the fix is a rate limit
whose baseline is the task's own observed shape rather than a global constant.
Catches: gradual resource accumulation, the slow exfiltration our side-channel
objective already showed we cannot see per call.

**b. Novel-counterparty holdback.** A first-ever destination is not the same
risk as a repeat one, even when both are in scope. Financial controls handle
this with a delayed-settlement or challenge window rather than a block. For us:
a first-contact destination gets a step-up, subsequent ones do not. This is
cheap, it directly addresses the slack failure mode (free-text destinations that
cannot be auto-trusted), and it converts a permanent friction into a one-time
one.

**c. Dual control for irreversible actions.** Consequence-scaled: reversible
actions proceed, irreversible ones above a threshold need a second authorization.
We have `is_consequential`; we do not have reversibility as a first-class axis.

**d. Structuring detection.** Our budgets catch a single over-limit call and
fragmentation against a fixed ceiling. They do not catch *shaping*: many calls
sized just under a threshold, which is the classic laundering pattern and the
exact analogue of an agent staying just inside every limit. The AML sensor
already validated on real fraud data (AUC 0.91) is the right component and is
currently not wired into the live path.

**How it would be judged.** The BPL scenario set already exists. Extend it with
velocity, novel-counterparty, and structuring classes, and report containment
per class with the false-alarm rate per 1,000 benign actions from the
long-trajectory tier, because a circuit breaker with a bad false-alarm rate is
worse than none.

---

## 3. Escapes: the syscall boundary is the only place some of this is decidable

We have two open holes that no amount of string-level policy can close, and both
are already documented in the code:

- **Symlinks.** `normalize_scope_path` resolves `..` lexically and cannot follow
  links. A symlink inside the granted workspace pointing outside it defeats
  every path check we have. The deny-list side is patched by matching both
  resolved and literal forms; the allow-list side cannot use that trick.
- **TOCTOU.** We authorize a path, then something else opens it. Nothing in the
  current design closes the window.

The kernel resolves paths for real, which is why iVisor is the answer rather
than a nice-to-have. The integration design already exists
(`docs/ivisor_integration.md`) and the seam is identified.

**What makes this SOTA rather than table stakes:** almost nobody evaluates agent
defenses against an agent *actively trying to escape the sandbox*, as opposed to
an agent following injected instructions. Our adaptive harness plus a real
syscall boundary would let us report containment against an escape-seeking
adversary, which is a category the published benchmarks do not cover at all.

**How it would be judged.** Containment of symlink, TOCTOU, procfs re-entry, and
mount-namespace escapes, measured with the enforcement overhead at p50/p95/p99
so the cost is visible. iVisor's own benchmarks put the syscall floor near
883ns, so the budget for an inline check is known.

---

## Priority

1. **Safety/usefulness frontier + audit budget** (item 1). Cheapest, uses
   existing machinery, and changes the artifact from "a number" to "a curve",
   which is what the field and a CISO both want.
2. **Velocity and novel-counterparty controls** (item 2a, 2b). Directly attacks
   the loss-of-control class our per-action layers are blind to, and 2b is a
   real answer to the slack friction rather than a workaround.
3. **Syscall boundary** (item 3). Highest ceiling, highest cost, and the only
   route to closing symlink and TOCTOU honestly.
4. Structuring detection (2d), which is mostly wiring an already-validated
   sensor into the live path.

## What not to do

- **Do not add more per-call authorization.** The coverage analysis says 82% of
  pooled attack events already leave the granted surface and we contain ~100% of
  them. The remaining 18% is in-surface, where per-call decisions are
  structurally blind, and no refinement of a per-call rule reaches it.
- **Do not tune against a single suite.** Two claims died this session for
  exactly that reason.
