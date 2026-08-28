# Methodology memo: how we kept from fooling ourselves

The goal of this project is a runtime security system that is actually state of
the art, not one that looks strong on its own harness. That distinction is the
whole memo. Below is the honest record of the self-deceptions this evaluation
nearly shipped, how each was caught, and the reusable discipline that caught it.
Read it before trusting any number in this repo.

## The core principle

Measure before you optimize, and make the measurement adversarial to your own
claim. Every time we did this, the result was different from the hypothesis, and
usually less flattering. That is the point. A security number you did not try to
break is a marketing number.

## The self-deceptions we caught

**1. The flagship claim was demonstrated only on a toy.** The business-process-
logic win (catching sub-threshold splitting that per-call defenses cannot see)
held on a bundled fixture and on nothing else. The adversarial synthesis for it
produced zero attack events on every real dataset, because it needed value
annotations only the fixture set. Caught by running the claim on real data
instead of citing the fixture. Fixed by annotating a real loader, then again by a
faithful authorized-replay attack, at which point it held on AgentDojo banking.

**2. A defense that did not hold its own guarantee.** The trajectory detector
advertised a conformally bounded false-alarm rate. On real corpora it ran at 17
to 27 percent false-block, and the rate did not move when we changed the
conformal budget. That last fact was the tell: an alpha sweep showed the false
alarms came from structural tiers that blocked outside the budget entirely.
Caught by sweeping the parameter the guarantee depends on and watching it not
respond. Fixed by subordinating those tiers to the same budget, after which the
bound held and containment on the unseen-aggregate class reached 95 percent.

**3. A number that did not survive an adaptive attacker.** The detector scored 75
percent on one corpus against a fixed attack. A defense-aware attacker that
fanned the aggregate across tools or kept it near benign volume dropped that to
27 and then 5 percent. Caught by attacking our own defense the way the field says
everyone should and almost no one does. Recorded as a corpus-dependent limit, and
the naive number was retracted.

**4. The wrong fix, prevented by a paired diagnostic.** We were about to build
graduated response to recover clean-utility loss, on the hypothesis that the loss
was recoverable step-ups. A paired per-task diagnostic (run each task under no
defense and under the defense, count only the tasks the defense actually flipped,
split hard-deny from step-up) showed zero step-up losses and that much of the
apparent loss was the agent failing on its own. The real cause was a read tool
misclassified as a write and hard-denied at the floor. The hypothesis would have
built the right feature in the wrong place and recovered nothing.

**5. Refusing to rewrite security tests to force a change.** A later fix demoted
order-violation denials to step-ups and broke five enforcement tests, including
sound landmark precedence (deploy before test). The tempting move is to update the
tests. Instead we recognized the change had over-reached beyond what the evidence
implicated, reverted it, and kept only the read fix the data supported. A test
that resists your change is data, not an obstacle.

**6. Two vulnerabilities we shipped, found by attacking ourselves.** The adaptive
red-team harness broke our own path scoping within an hour of existing.
`path_matches_any` fnmatched the raw string, so a `/app/**` workspace grant
returned True for `/app/../etc/passwd`, which `open()` reads as `/etc/passwd`.
Every rung that scopes by path inherited it, and the protected-zone deny-list
missed it too because it string-matched the same unresolved input, so defense in
depth did not apply. The second was procfs re-entry: `/proc/self/root/etc/passwd`
addresses the whole filesystem behind a prefix no pattern recognised, and
resolving it lexically is actively wrong because popping a symlinked component
is the wrong operation. Caught by building an adversary that searches rather
than a corpus that replays.

**7. A red-team harness that produced fabricated findings.** Three times, the
adaptive search reported escapes that accomplished nothing. `/app/etc/passwd`
matched the sensitive-path marker by substring while being a file inside the
agent's own workspace. `/app/etc/cron.d/agent` scored as persistence for the
same reason and handed `task-scope` a false 0%. And informed mutations consumed
the whole per-round budget, crowding out the plain obfuscation that actually
worked, so the persistence run reported 46% containment against an ORACLE
attacker and 0% against a BLIND one. Published unchanged, that table would have
claimed that disclosing your policy helps the defender. The lesson: an adaptive
search optimises against whatever you actually wrote down, so the objective
predicate is the experiment.

**8. A 50-point improvement from a defense that was not running.** A new
ablation name missed every key in an exact-name planner dictionary, got
`planner=None`, and therefore built no intent envelope. The run reported 8 of 8
tasks and zero denials: a perfect score for a defense that was absent, with no
error raised. What caught it was the mechanism disagreeing with the number. The
change converted hard denials into step-ups, and a step-up halts execution
exactly as a denial does, so autonomous utility *could not* improve. The number
said it had. The identical pattern was later found in a second file before it
could do the same thing there. Silent and flattering is the failure mode to
engineer against.

**9. The strongest result of the session, retracted by validation.** Allowing an
off-plan action when the binding floor had validated its destination took
banking clean utility from 16.7% to 50.0% at 0.0% ASR, with friction to zero. It
looked like the whole utility cost removed for free. Travel took ASR from 5.6%
to 27.8%. The motivating argument, that the plan-conformance gate catches
nothing the floor missed, is true on banking and false in general. The flag
remains in the tree defaulted off, because that is how the negative result
reproduces.

**10. The axis we assumed was solid.** We treated clean utility as the noisy
measurement and attack-success rate as reliable. The same workspace
configuration then produced 27.8% ASR in one sweep and 0.0% in another: same
code, same suite, same model, same attack, n=18 both times. Every 0% ASR in this
repository comes from a single sweep, and the Wilson upper bound on 0 of 18 is
17.6%. The security claim was supported to roughly one significant figure while
being quoted to three.

**11. A regression that was a coin flip.** During a performance pass, a change to
the confidentiality tracker was checked against `benchmarks/flow.py` before and
after. The 22-fragment concurrent arm went from 150 of 200 to 158 of 200, which
reads as containment getting worse and is the kind of number a careful person
stops on.

It was noise. That arm races writers through a thread pool, so it is not a
function of the seed, and two runs of the *same* commit give 170 of 200 and 155
of 200. Five runs a side put the means at 152.4 and 152.6 with fully overlapping
ranges. The change had no effect on containment at all.

Two things were wrong and only one of them was the reading. The benchmark
published a draw from a distribution as though it were a measurement: a single
pooled count, no spread, and the only hint anywhere was a line of prose in
`flow.md` saying the tail moves between draws. Anyone doing what we did would
have reached the same wrong answer, and the alternative failure is worse — a real
regression of 8 points would have been dismissed as noise by someone who had
learned to distrust the arm.

Fixed at the instrument rather than in the reader's head. The stochastic arms
now print `NOT SEEDED` with their per-trial spread, carry `"stochastic": true` in
the JSON, and `docs/benchmark_program.md` states the comparison rule: establish
the noise floor by running the same code twice BEFORE reading any before-and-after.
That step is the one that gets skipped, and it is the one that decides whether
the comparison means anything.

## The strongest results, with what each is not allowed to claim

Reproduce the deterministic tiers with `benchmarks/run_all.sh` against the
corpus pinned in `benchmarks/corpus_manifest.json`. A full pass is CPU-only and
takes under a minute.

**Long-horizon detection.** 200 sessions of 500 benign actions with one attack
buried in each: **100% needle detection at zero false alarms across 100,000
benign actions**, holding at 2,000-action sessions. This is the only tier where
argument binding separates from path scoping, closing the final 17 points that
`capability-token` and `task-scope` leave open. Published benchmarks average
about three calls per trajectory and structurally cannot show that difference
exists. *Does not claim:* anything about in-surface attacks, which this tier does
not contain.

**Adaptive containment.** 100% containment across exfiltration, persistence, and
destruction objectives, flat across blind, feedback, and oracle attacker
knowledge. Telling the attacker the compiled policy buys it nothing, because the
defense constrains the outcome rather than the input. *Only as good as its
control:* a prefix matcher without canonicalisation is checked in as a test that
must keep failing, and it falls 80 of 80 at round 1.

**Best live operating point (workspace).** 0.0% ASR at 100% clean utility,
matching the undefended baseline exactly, for 1.50 interruptions per task.
Attack success falls from 83.3% to zero and utility under attack rises from
27.8% to 83.3%. *Caveat that matters:* single sweep, n=18, so the honest interval
on that 0.0% is [0, 17.6%] until the pooled re-run lands.

**Utility cost against the published bar.** Pooled over four suites and 32 clean
tasks, paired per task so only defense-caused losses count: the deployable
envelope costs **3 points on grok-4-1-fast** against an 81% baseline, where CaMeL
reports 7 points against 84%. The cost falls monotonically with model strength
(25 points on gpt-4o-mini, 19 on gpt-oss-120b, 3 on grok-4-1-fast), which says
most of what we had been reporting as the cost of enforcement is the cost of a
weak agent. *Does not claim:* that we beat CaMeL generally. On gpt-4o-mini we do
not.

**What the layer cannot decide, stated first.** 82% of pooled attack events
leave the granted surface and we contain about 100% of them. The remaining 18%
stay inside it, and every per-call authorizer including ours contains roughly
none of that class. Pooled over all 3,410 events the full stack contains 82.1%,
not the 100% the surface-leaving column alone suggests. Publishing the weighted
number pre-empts the objection rather than waiting for it.

**Cost.** 34us at p50 at the `Guardrail` boundary, four orders of magnitude below
the LLM round trip it gates. The median is the least interesting number here: the
argument-size dependence, the confidentiality tail and the unbounded per-session
memory all matter more, and all three are in the one place these figures now live,
[benchmarks/results/performance.md](../benchmarks/results/performance.md). This
line used to quote 35us/60us with no statement of which measurement point it came
from, which is how four different p50s ended up in four different files.

**Enforcement ladder on RedCode.** All 717 attacks leave the surface via the
target alone, so `tool-allowlist` and `capability-token` contain **zero** while
`task-scope` contains 100% at 0% false-block. A clean single-variable
demonstration that authority must bind to the target rather than the tool name.

## The reusable tools

- **Paired causal attribution.** Never attribute a failure to your system without
  a control. Run with and without it on the same input; count only what flipped.
- **Separate the recoverable from the fatal.** A hard deny of a benign action is a
  false-positive. A step-up is a confirmation that succeeds under supervision.
  Reporting them together (autonomous utility) understates a system meant to run
  with a human on the escalation path. Report both.
- **Sweep the parameter your guarantee rests on.** If the guaranteed quantity does
  not respond to its own knob, the guarantee is not wired to the outcome.
- **Attack your own defense adaptively.** The residual under a defense-aware
  attacker is the real number. A fixed-attack score is an upper bound on your own
  competence, not on the attacker's.
- **Block on positive evidence, step up on absence.** Hard-deny only with positive
  evidence of malice (untrusted-origin destination, payload mutation, protected
  zone). Absence of authorization is uncertainty, so it steps up. This recovers
  benign utility without weakening security, because the attack carries the
  positive evidence and the step-up still halts it.
- **Name your leaks.** If benign examples are clean by construction, a detector
  can score perfectly by reading the label. We did not report such a number and
  neither should anyone.
- **Grade someone else's homework.** Our attacks are our own synthesis. That is
  fine for a mechanism claim and must be labeled, and validated against external
  corpora where they exist.
- **Price every resource the defense spends, including attention.** A protocol
  that reaches 0% ASR by asking the human about everything has relocated the
  vulnerability, not removed it, and approval fatigue is an attack surface. On
  banking, `graduated` reaches the same 0.0% ASR as the shipping configuration
  while spending 4.17 interruptions per task against 0.83, for half the clean
  utility. Measured on two axes that reads as a tie. Measured on three it is
  strictly dominated. Human attention is now a bounded, charged resource
  (`audit_budget`) rather than a free one.
- **Choose the validation suite that could refute you, not the one that agrees.**
  `deferallow` was safe on banking and slack and broke travel and workspace. The
  two that agreed are exactly the two that would have been quoted. A per-suite
  result is a per-suite recommendation, and the deployment decision is the
  intersection across suites, never the union.
- **Make the objective predicate independent of the defense.** An adaptive search
  rewarded for "getting allowed" will find mutations that are allowed because
  they no longer do anything. Every candidate is scored against a real-world
  effect defined without reference to any engine, and predicates resolve paths
  before judging them and ignore anything landing inside the granted workspace.
- **Prefer failures that are loud over failures that flatter.** Both harness bugs
  this session produced perfect scores and raised no error. Resolution by shape
  with a hard refusal when nothing resolves turns a silent wrong answer into a
  startup failure.
- **Trust the mechanism over the number when they disagree.** The fabricated
  50-point win was caught because the change could not raise autonomous utility
  by construction, and the measurement said it had. When a result exceeds what
  the mechanism can explain, the measurement is the suspect.
- **Report per-action counts beside per-task rates.** At n=8 a single task is
  12.5 points. Across every comparison this session the action-level counts
  (hard denials, step-ups) moved cleanly and in the predicted direction while
  the task-level percentages wandered.

## The open questions we did not resolve

**How many runs is a security claim?** Item 10 above is unresolved as of this
writing. Every attack-success number here rests on a single sweep of n=18, and
we have direct evidence that such a sweep can move 27.8 points. Pooling four
suites would bring the interval on a clean result to about [0, 5.1%], and twelve
sweeps to [0, 1.7%]. Until that lands, "0% ASR" should be written with its
interval or not written at all. The tooling exists
(`benchmarks.live.frontier --repeats N`), the run is queued, and no security
claim should leave this repository ahead of it.



AgentDojo utility is autonomous task completion. A system that asks a human to
confirm an irreversible action is behaving correctly, yet the metric scores that
as failure. Supervised utility is a partial answer, but the honest framing is that
autonomous completion is a lower bound on the value of a supervised system, and no
single benchmark number captures the tradeoff we actually care about. Any headline
utility figure carries that caveat.
