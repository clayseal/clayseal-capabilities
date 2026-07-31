# Dynamic sandbox v0.2 roadmap

Where v0.1 ended and what v0.2 has to prove. v0.1 established that the sandbox
generalizes across ontologies with zero tuning. v0.2 has one job: turn a defense
that looks strong against fixed attacks into a defense with a demonstrable safety
envelope and a deployable path. Everything below is scoped to that.

This file is the durable roadmap. The design rationale lives in
[dynamic_sandbox.md](dynamic_sandbox.md); the v0.1 numbers live in
[../benchmarks/results/held_out_generalization.md](../benchmarks/results/held_out_generalization.md).

## v0.1, done and recorded

- Whitelist-not-blacklist containment shipped: capability floor, destination
  binding, partial-order structural conformance, two-signal danger gate,
  advisory statistical sensor. One gateway, one receipt per action.
- Held-out suite generalization: the sandbox designed on banking cut attack
  success by 81 to 95 percent on workspace, travel, and slack with no per-suite
  tuning. All four suites now sit at 0 to 8.3 percent full-stack ASR.
- Read-permissive / effect-strict scoping: containment scales with
  reversibility. Doubled travel deployable utility from 25 to 50 percent with
  ASR improving.
- Egress-on-reads: destination binding now runs on any action carrying an
  external destination, not only effect verbs, which closed the slack SSRF-style
  read-to-attacker-URL channel (20.8 to 0 percent at 87.5 percent utility).
- Held-out attack types: the full stack held ASR at 0 percent against four
  injection strategies it was never designed for (tool_knowledge 38.9 to 0,
  ignore_previous 33.3 to 0, system_message 16.7 to 0, injecagent 27.8 to 0).
- 147 tests green across all of the above.

This satisfies items 1 and 2 of the anti-overfit contract in
[dynamic_sandbox.md](dynamic_sandbox.md). Items 3 and 4 are the v0.2 keystones.

## v0.2 keystones

### 1. Adaptive envelope-aware adversary (decisive test, RUN: full stack 0% ASR)

The one number that separates a real safety envelope from a defense that only
looks strong against fixed attacks. An attacker that knows the defense and
optimizes to evade it: stay in scope, satisfy verb-class order, mimic the plan,
suppress the confirmation step-up.

The attacker is built and registered at
[../benchmarks/live/adaptive_attack.py](../benchmarks/live/adaptive_attack.py).
It blends the malicious action into the authorized manifold: prepend a benign
in-scope read to satisfy gather-before-act, frame the attack as a routine task
continuation, and suppress the step-up. The scientific point is sharp: the
attacker cannot rewrite the malicious goal's destination, so where binding
applies it should still fail. Whatever residual it leaves measures the true
frontier (wrong-target arguments and output manipulation), not a phrasing
weakness.

Result (banking, n=18, recorded in
[../benchmarks/results/adaptive_adversary.md](../benchmarks/results/adaptive_adversary.md)):
full stack held ASR at **0%** against the defense-aware attacker; deployable
envelope cut ASR 38.9 to 16.7% at a utility cost. The 0% ceiling is the headline
v0.2 number and the 16.7% deployable residual is the read-then-send class that
keystone 2 closes. Remaining: run the same attack across the held-out suites
(workspace, travel, slack).

### 2. Deployable provenance / taint layer (shippable-guarantee keystone)

Item 4 of the contract. The strongest v0.1 numbers use ground-truth scope and
destination seeding (the oracle). The deployable system must reach the same
containment from the goal plus data-flow, with no oracle. The rule: an effect
action whose arguments are tainted by untrusted tool output, rather than by a
trusted-named resource, is denied. This is the CaMeL data-flow direction and the
only principled catch for the read-then-send class.

This is what converts the ceiling numbers into a guarantee a design partner can
run. Until it lands, every headline result carries the oracle caveat, stated
plainly, not hidden.

Progress (banking, n=18, recorded in
[../benchmarks/results/provenance.md](../benchmarks/results/provenance.md)): the
goal-seeded egress binding (`envelope-provenance`) reaches **0% ASR with no
oracle**, matching the ceiling. Security half met. Utility half open: clean
utility drops to 16.7% because goal-text seeding over-blocks benign transfers
whose recipient is not literally in the prompt. Next: widen the trusted seed from
goal-text to origin-based taint over pre-contamination environment state (the
CaMeL data-flow direction), to recover utility while holding ASR at 0.

### 3. Graduated response (from the Schneier memo)

v0.1 blocks. The memo's runtime-anomaly framing asks for a graduated response
instead: when the action stream drifts from the goal-consistent distribution,
steer the agent back toward intended actions first, escalate to a user-permission
prompt for follow-on lines of action, and hard-block only the bound violations
(payload mutation, out-of-scope effect, egress off policy). This maps the
two-signal danger gate onto three outcomes (steer, ask, deny) keyed on deviation
times consequence and reversibility, rather than a single block. It is the
difference between a sandbox that stops attacks and a partner that stays
productive while staying safe.

Depends on the danger gate already in place; additive, not a rewrite.

## Dataset breadth (already in the harness)

v0.2 measurement runs beyond AgentDojo. The dataset adapters live in
[../benchmarks/datasets/](../benchmarks/datasets/): AgentDojo, BFCL, TAU2,
InjecAgent, ATIF, ToolEmu, plus the fraud validation set
([../benchmarks/fraud_validation.py](../benchmarks/fraud_validation.py)). The
v0.2 task is not adding datasets, it is running the three keystones across the
ones already wired and recording each result with its honest caveats.

## Carried-forward limits (do not hide)

- Output manipulation with no tool call is invisible to an action-gating
  sandbox. The sandbox governs actions, not speech.
- In-goal wrong-target actions (a legitimately scoped destructive tool aimed at
  the wrong object) need argument binding or provenance to separate from the
  benign call.
- The oracle gap above is the reason keystone 2 exists.

## Parallel track: Project 2, CVE and disclosure triage

The memo names a second, narrower project that does not yet exist in any repo.
Ingest a newly disclosed agent failure (paper, CVE, bug bounty, incident),
extract the failure pattern, map it against a target's agent workflows or
codebase structure, and emit concrete checks plus, where one applies, the runtime
control from this sandbox that would have stopped it. The useful output is one
answer: could the same kind of failure happen in our agent system.

This reuses the red-team corpus already in the repo docs and turns the sandbox's
layers into named mitigations. Scoped as a separate deliverable, sequenced after
the three keystones unless prioritized sooner.

## Sequence

1. Run the adaptive adversary, full stack, banking then held-out suites. Headline
   v0.2 number.
2. Build the provenance / taint layer, re-run the suites with oracle seeding
   removed, report the deployable delta.
3. Add graduated response, measure utility-under-attack lift with ASR held.
4. Project 2 as a separate track.
