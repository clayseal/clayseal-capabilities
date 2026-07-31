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

## The open question we did not resolve

AgentDojo utility is autonomous task completion. A system that asks a human to
confirm an irreversible action is behaving correctly, yet the metric scores that
as failure. Supervised utility is a partial answer, but the honest framing is that
autonomous completion is a lower bound on the value of a supervised system, and no
single benchmark number captures the tradeoff we actually care about. Any headline
utility figure carries that caveat.
