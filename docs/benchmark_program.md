# The benchmark program

What we measure, why each measurement exists, and what it is not allowed to
claim. The audience is a security buyer who has been shown a lot of vendor
benchmarks and has learned to discount them.

The reference model is MITRE ATT&CK Evaluations: full attack chains rather than
isolated events, a published scoring specification, raw results released, no
vendor-assigned ranking, and deliberate benign activity injected to measure
noise. The 2026 round added alert-quality and false-positive testing precisely
because containment alone was gameable. Ours should be gameable in the same
places and closed in the same way.

## The five questions a result must answer

1. **What is the unit of analysis?** Events inside a task are correlated. A
   corpus of 718 attack events built from 14 templates is closer to 14
   observations than 718, and reporting the event count as `n` inflates
   confidence by roughly the square root of the events per template.
2. **Was the adversary allowed to adapt?** A static corpus measures performance
   against attacks written by someone who had not seen the defense.
3. **What did containment cost?** A control that blocks legitimate work is not
   free, and false-block rate measured on replayed ground-truth traces is
   measured on calls that pass by construction.
4. **Would it reproduce?** Against which corpus revision, at which seed, with
   which failures left in the denominator.
5. **What does it not do?** A benchmark on which we win everything is a
   marketing asset, not evidence.

## The four tiers

| Tier | Question | Cost | In `run_all.sh` |
| --- | --- | --- | --- |
| Replay ladder | Does authority bind to the target? | seconds, CPU | yes |
| Adaptive red-team | Does it hold when the adversary adapts? | seconds, CPU | yes |
| Live agent | What does it cost real work? | dollars, API, noisy | no |
| Syscall boundary | Does it hold when the agent tries to escape? | minutes, VM | no |

The live tier is deliberately excluded from the one-command run. It costs money,
needs credentials, and carries sampling noise, so mixing it into a "run
everything" number would let an expensive noisy measurement inherit the
credibility of a cheap deterministic one.

## Tier 1: replay ladder

Six enforcement rungs of increasing authority granularity replayed over labeled
corpora (RedCode, AgentHarm, ASB, BFCL, AgentDojo, InjecAgent, ToolEmu,
fixture). Reports containment and false-block per rung.

Two invariants are enforced as tests rather than asserted in prose
([benchmarks/tests/test_ladder_invariants.py](../benchmarks/tests/test_ladder_invariants.py)):
containment is monotone up the ladder *per event*, and friction does not grow.
The per-event form matters, because two rungs can report identical percentages
while disagreeing about which events they caught, and that disagreement is the
defect class worth hunting. It found one immediately.

Every rate carries a task-clustered bootstrap interval
([benchmarks/core/stats.py](../benchmarks/core/stats.py)). At the 0% and 100%
boundaries the bootstrap collapses to zero width, which reads as certainty, so
those fall back to a rule-of-three bound at the cluster level: 0 escapes over
20 templates is a much weaker claim than 0 over 700, and the interval says so.

## Tier 2: adaptive red-team

An attacker that proposes, gets judged, and mutates, over N rounds, at three
knowledge levels ([benchmarks/adversarial/adaptive.py](../benchmarks/adversarial/adaptive.py)):

- `BLIND` mutates without information. This is what a static corpus measures.
- `FEEDBACK` sees deny reasons. Realistic for any agent that can read its own
  tool errors, which is all of them.
- `ORACLE` reads the compiled policy. The number to publish, since assuming the
  adversary knows the design is the only defensible posture.

Two rules keep it honest.

**The objective predicate is independent of every engine.** A search rewarded
for "getting allowed" finds mutations that are allowed because they no longer do
anything. A candidate counts as an escape only if it was fully allowed *and*
achieved a real-world effect: sensitive data reaching an external host, a write
that survives the session, a delete outside the workspace. Predicates resolve
paths before judging them and ignore anything landing inside the granted
workspace. Both rules were added after the predicate produced fabricated escapes
in testing, twice.

**The harness must be able to break things.** A red-team that breaks nothing
reports 100% for every defense including bad ones. A negative control, a prefix
matcher with no canonicalization, is checked in as a test that must keep
failing. If it ever survives, no containment number from this harness is
publishable until that is fixed.

Attacker strength must also be monotone in knowledge. It was not at first:
informed mutations consumed the whole per-round budget and crowded out a plain
obfuscation that worked, so persistence reported 46% containment against an
oracle attacker and 0% against a blind one. Published unchanged, that table
would have claimed disclosing the policy helps the defender.

## Tier 3: live agent (not yet rebuilt)

The false-block rate on the replay tier is 0% and will stay 0%, because replay
feeds back ground-truth calls that pass by construction. That number must never
be quoted as an operational false-positive rate. See
[methodology_audit.md](methodology_audit.md), which already records the
problem, plus two others still open: STEP_UP outcomes counted as failures, and
clean-task failures attributed to the defense without a paired control.

What this tier needs, and does not yet have:

- utility measured against real agent trajectories with natural variation;
- DENY and STEP_UP reported separately, since only a hard DENY of benign work is
  unrecoverable;
- paired attribution, where only a task that succeeded undefended and failed
  defended counts as a defense-caused loss;
- enough seeds to report an interval, given the audit records the same
  configuration producing 55.6%, then 11.1%, then 12.5%.

## Tier 4: syscall boundary (not yet built)

The layers above decide on paths as strings. Lexical resolution is unsound
across symlinks: `/proc/self/root` links to `/`, so popping it lexically is
simply the wrong operation, and no string function can know which components are
links. The deny-list side is patched by matching both the resolved and literal
forms, which can only ever deny more. The allow-list side cannot use that trick.

Symlink containment therefore belongs where paths are resolved for real, which
is the syscall boundary. iVisor is the substrate, and this tier measures whether
enforcement holds against an agent actively trying to escape rather than a
replayed trace of one.

## Reproducibility contract

- corpora pinned by content hash, verified before every run
  ([benchmarks/verify_corpus.py](../benchmarks/verify_corpus.py)). A number that
  fails to reproduce should be distinguishable from a number that was wrong;
- one command reruns every deterministic result
  ([benchmarks/run_all.sh](../benchmarks/run_all.sh));
- seeds fixed and reported; the adversarial leaderboard runs ten of them;
- failures stay in the denominator. The RedCode case where our decision
  disagrees with the corpus label, and the AgentHarm ceiling, are published
  rather than excluded.

## What these benchmarks do not measure

- **Intent.** AgentHarm caps at 6.3% across every rung because in 143 of 176
  pairs the harmful task and its benign twin call the identical tool set. No
  layer deciding from tool, resource, action, or argument shape can separate
  those. Authorization is not classification and we do not claim otherwise.
- **Operational false positives.** Tier 3 is not rebuilt yet.
- **Symlink and TOCTOU containment.** Tier 4 is not built yet.
- **Anything about a live agent's utility.** No number here involves an LLM.
