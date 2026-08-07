# Clay Seal: runtime containment for AI agents

## The problem

Every enterprise deploying AI agents faces the same structural gap. An agent is
given tools and a goal, and the only thing standing between a compromised agent
and the company's data is the model's own judgment. Prompt injection turns that
judgment against you: attacker text arrives inside a document, an email, or a
web page the agent was legitimately asked to read, and the agent then acts on it
using credentials it legitimately holds.

Existing controls do not reach this. Tool-level RBAC authorizes *what kind of
action* an agent may take, never *what it may act on*. On RedCode-Exec, a
NeurIPS benchmark of 718 risky operations, tool-name allowlists and
`resource:action` capability tokens contain **zero**. Every attack uses a tool
the agent legitimately holds and differs only in the target.

## What we built

Clay Seal binds authority to the **target and the outcome**, not the tool name.
A sealed goal compiles into a machine-checkable envelope: which paths, which
destinations, which argument shapes, and what aggregate volume the task may
consume. Every action passes a single gateway before it executes, and every
decision lands on a hash-chained audit log.

The layered design is what makes it hold. Target binding stops the wrong file.
Destination binding stops the wrong recipient. Aggregate budgets stop the attack
that stays inside every per-call rule and wins on volume. Plan conformance stops
the action that fits every rule and was never part of the job.

## Results

Deterministic tiers reproduce in under a minute on CPU with `benchmarks/run_all.sh`
against a content-pinned corpus.

**Containment against a live prompt-injection attack.** On AgentDojo workspace,
attack success falls from 83.3% undefended to **0.0%**, at **100% clean
utility**, matching the undefended baseline exactly. Utility under attack rises
from 27.8% to 83.3%. The published alternative, Progent, leaves 11 to 17% attack
success across suites.

**Utility cost at or below the state of the art.** Pooled over four suites and
32 clean tasks, paired per task so only defense-caused losses count, the
deployable configuration costs **3 points of task completion on grok-4-1-fast**
against an 81% undefended baseline. Google DeepMind's CaMeL, the strongest
published comparable, reports 7 points against 84%. The cost falls monotonically
as the agent gets stronger: 25 points on gpt-4o-mini, 19 on gpt-oss-120b, 3 on
grok-4-1-fast. Enterprises deploy the strong end.

**Containment holds against an adversary that knows the design.** Our red-team
harness lets the attacker read the compiled policy and try again over multiple
rounds. Containment is **100% across exfiltration, persistence, and destruction
objectives, and flat across all attacker knowledge levels**. Disclosing the
policy buys the attacker nothing, because the system constrains the outcome
rather than the input phrasing.

**It works over real session lengths.** In 200 sessions of 500 legitimate
actions each with one malicious action buried inside, we detect **100% of the
needles at zero false alarms across 100,000 benign actions**, holding at
2,000-action sessions. Published agent-security benchmarks average about three
tool calls per task and cannot measure this at all. It is also the tier where
argument binding demonstrably earns its place, closing the last 17 points that
path scoping alone leaves open.

**Fast enough to be invisible.** 35 microseconds at median, 60 at p99, roughly
four orders of magnitude below the LLM call it gates.

**Honest about scope, which is itself a differentiator.** We classify attacks by
whether they leave the granted surface. 82% do, and we contain essentially all
of them. The remaining 18% stay entirely inside it, where every per-call
authorization system including ours is structurally blind. We publish the
weighted number, 82.1%, rather than the flattering one. Buyers who have been
shown a lot of vendor benchmarks notice.

## Why this is defensible

**The evaluation is the moat as much as the enforcement is.** We built an
adaptive red-team that searches against the policy rather than replaying a fixed
corpus. Within an hour of existing it found two exploitable vulnerabilities in
our own shipping code: a path-traversal bypass where a workspace grant admitted
`/app/../etc/passwd`, and a procfs re-entry bypass reaching the filesystem root
behind a prefix no pattern recognized. Both are fixed with regression tests.

That capability generalizes. Any company deploying agent authorization has the
same class of bug and no way to find it.

**We measure a cost nobody else reports.** A defense that reaches zero attack
success by asking a human to confirm everything has moved the problem, not
solved it, and approval fatigue is itself an attack surface. We report human
interruptions per task alongside safety and utility, and bound them with an
explicit attention budget. On one configuration this exposed a setting that
reached identical security while spending five times the human attention for
half the utility. On two axes it looked like a tie.

**The audit trail is a product surface.** Every decision is hash-chained and
verifiable, which is what regulated buyers need to demonstrate control rather
than assert it.

## Evidence quality

Deterministic tiers run at large n and reproduce exactly: 3,410 attack events
across the coverage analysis, 100,000 benign actions in the long-horizon tier,
10,880 decisions per engine in the latency measurement, and 512 tests passing.

Live measurements involve a stochastic agent and currently run at n=18 per
configuration per suite. A pooled multi-sweep run is in progress to tighten the
intervals on the live attack-success figures; the deterministic results above
are unaffected. We would rather state that than quote a point estimate to three
significant figures.

## Where this goes next

**In-surface attacks** are the open frontier for the whole field. The 18% that
stay inside the granted surface are where real incidents come from, and nobody
contains them today. Velocity and shape controls, plus provenance tracked across
the data-flow graph, are the route, and our aggregate-budget layer is already
the only rung that sees any of that class.

**The syscall boundary.** Symlink resolution and time-of-check/time-of-use are
undecidable in userspace by construction. Enforcing at the kernel boundary
closes them and would let us evaluate against an agent actively trying to escape
its sandbox, a category no published benchmark covers.

**Evaluation as a standard.** The three-axis frontier, reported with adaptive
attackers and long-horizon false-alarm rates, is the artifact the field is
moving toward and does not yet have. Standards outlive scores.

## Reproduce

```bash
benchmarks/fetch_corpora.sh     # pinned external corpora, ~4 MB
benchmarks/run_all.sh           # every deterministic result, under a minute
python -m benchmarks.live.frontier --suite workspace --repeats 3
```
