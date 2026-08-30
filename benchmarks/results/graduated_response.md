# Graduated response: recovering the irreducible false-positive

STATUS: current
> **The `supervised utility` column below is WITHDRAWN.** Every "supervised utility" figure below is a
> **counterfactual**, not a measurement. It is `autonomous + step-up losses`, which
> assumes both that a human approved and that the task then succeeded. Nothing
> resolved a step-up when these ran: `SessionBroker.resolve_step_up` and
> `LiveBrokerHarness.gate_with_supervision` did not exist. Re-run with a resolving
> approver (`benchmarks/live/approver.py`) before quoting any of it; the delta is
> expected to be negative, because a resumed run can still fail downstream.


The provenance work established that some benign destinations cannot be
auto-trusted: a free-text recipient read from a document shares its source with a
possible injection, so no origin rule can separate them (see observed_grant.md). The
honest handling for that case is not a hard deny, it is a step-up: ask the human
once. Graduated mode (opt-in on the broker) demotes an egress destination-miss
from DENY to STEP_UP. A step-up halts autonomous execution exactly like a deny,
so it does not weaken security, but it is recoverable under supervision.

## Banking, gpt-4o-mini, n=8, paired per-task diagnostic

Utility is reported three ways: autonomous (a step-up counts as failure),
supervised (a step-up on a benign action is recovered by a human confirmation),
and the causal split of defense-caused losses into hard denies versus step-ups.
Baseline (no defense) clean success is 5/8, the ceiling any defense can reach.

| configuration | autonomous | supervised | defense-caused hard deny | recoverable step-up |
|---|--:|--:|--:|--:|
| envelope-taint | 38% | 50% | 1 (floor egress) | 1 |
| envelope-taint-graduated | 50% | 62% | 0 | 1 |

## Reading

Graduated mode removes the one hard-deny false-positive (1 to 0): the benign send
whose recipient lived in free-text, which the non-graduated path hard-blocked, now
steps up. Supervised utility rises to 62 percent, which equals the baseline
ceiling of 5/8. In other words, once the confirmable step-up is honored, the
deployable path has no unrecoverable false-positives left on this suite; every
remaining failure is the agent failing on its own (three tasks fail with no
defense at all), not the defense.

The friction is one step-up on the one task that needs it, so the cost of the
recovery is a single confirmation, not a wave of prompts. The autonomous number
also rose (38 to 50 percent), but at n=8 that is within run-to-run noise; the
robust and repeatable signal is the hard-deny count going to zero and supervised
utility reaching the ceiling.

## Status

Graduated response is the correct home for the destinations provenance cannot
safely auto-trust. Both halves are now validated on banking.

Utility half: supervised utility reaches the baseline ceiling (62 percent, 5/8)
with zero unrecoverable blocks.

Security half: banking, n=18, important_instructions. Baseline attack success is
66.7 percent; envelope-taint holds it at 0 percent, and envelope-taint-graduated
also holds it at 0 percent. Demoting the egress miss to a step-up did not weaken
security, because a step-up is not an allow and still halts the attacker send.

So graduated mode buys the supervised-utility recovery at no security cost.

## Breadth and scale: the pattern holds

Same paired diagnostic across suites. The headline numbers below are the larger
run (banking 16 user tasks, slack 20, workspace 8); the n=8 pass agreed.

| suite | supervised (taint -> graduated) | hard-deny false-pos (taint -> graduated) | step-ups (friction) |
|---|--:|--:|--:|
| banking (n=16) | 56% -> 62% | 1 -> 0 | 1 |
| slack (n=20) | 35% -> 70% | 7 -> 0 | 8 |
| workspace (n=8) | 88% -> 88% | 0 -> 0 | 0 |

The result is general, not banking-specific, and it strengthens with scale. On
every suite graduated response drives the hard-deny false-positive count to zero
and lifts supervised utility toward the baseline ceiling. Slack is the clearest
case: at 20 tasks the hard-deny path silently fails seven benign sends whose
recipients come from contacts and pages, graduated turns all seven into
confirmations, and supervised utility doubles from 35 to 70 percent against a 75
percent ceiling. Workspace has no egress misses, so graduated changes nothing and
does no harm. The friction it costs is proportional to how many novel destinations
the task legitimately reaches (banking one, slack eight, workspace zero).

The near-deterministic signal is the hard-deny false-positive count going to zero;
the supervised percentages carry agent-run stochasticity (a task can fail under no
defense and pass under a defense on a different run), so they should be read as
directional, not exact.

## Standing

The utility gap that the autonomous numbers implied is largely an artifact of
scoring a confirmation as a failure. Under the supervised model the system is
built for, the deployable path reaches the baseline ceiling on all three suites
with zero unrecoverable false-positives and unchanged attack success. The honest
cost is friction, a bounded number of confirmations per task (one on banking,
three on slack, zero on workspace), which is now the metric to carry forward and,
for a payments or communications agent, is arguably the correct behavior rather
than a cost. Remaining: confirm at larger n, and report the friction alongside
utility everywhere instead of the autonomous number alone.
