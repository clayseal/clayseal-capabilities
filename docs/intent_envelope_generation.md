# Generating the Intent Envelope (Phase C)

How to produce the goal-derived envelope from a sealed natural-language prompt.
Research synthesis and design. Companion to `intent_envelope_design.md`.

## The problem

Phases A and B assume the envelope already exists (authored via
``structured_intent``: phases, goal conditions, a tool ontology). Phase C is the
hard part the memo points at: **estimate a plausible envelope of action paths**
from the sealed goal, automatically, once, on trusted input. This is exactly the
memo's "distribution of likely actions," and its own analogy (Waymo) tells us the
shape of the answer.

## 1. The envelope is a distribution over plans, not one golden path

The single most important correction to Phases A and B: real tasks are
**multi-modal**. There is usually more than one legitimate way to accomplish a
goal, and until the agent commits, several should be considered plausible.

This is precisely how self-driving predicts behavior.
[MultiPath (Waymo)](https://waymo.com/research/multipath-multiple-probabilistic-anchor-trajectory-hypotheses-for-behavior-prediction/)
predicts a discrete distribution over a set of **anchor** trajectories, each a
mode of the future, because "in a lane with arrows for both straight and left, a
vehicle could do either, and until the driver signals intent both are equally
plausible." The agent envelope should be the same: a set of **anchor plans**
(modes), each a plausible decomposition of the goal, each with a probability.
Conformance becomes "does the trace track one of the anchors," not "does it match
the single golden path." This removes the rigidity that made Phase A over-block
legitimate variation.

The memo's phrase "estimate a plausible envelope of action paths" is a
mixture-of-plans, and "distribution of likely actions" is the discrete
distribution over the anchors. Both are Waymo behavior prediction, ported.

## 2. Generation = sample the plausible-trace distribution at seal time

How does an autonomous stack get its distribution of plausible scenarios?
[Scenic](https://arxiv.org/abs/2010.06580), a probabilistic programming language
used by Boeing, Toyota, Meta, and others, defines a distribution over scenarios
and **samples** concrete ones. And
[ScenicNL](https://openreview.net/forum?id=MNLAbfZwh2) generates those
probabilistic scenario programs **from natural language**.

Ported to agents: compile the sealed goal into a generator of plausible plans,
then sample it to get the anchor set. Concretely, sample a planner K times
(temperature or top-k), which is exactly LLM **self-consistency** (sample many
reasoning paths; the recurring ones are high-probability). Cluster the K plans
into modes; the frequency of each cluster is its probability. That frozen mixture
is the envelope. This is Monte-Carlo scenario sampling from the goal, done once.

## 3. Injection-safe generation: the privileged planner and the Ulysses pact

Generation must read the goal but never the untrusted content that could
contaminate it. This is not a new requirement to invent; it is a named pattern.

[CaMeL (Google DeepMind)](https://simonwillison.net/2025/Apr/11/camel/) splits the
agent into a **Privileged LLM that plans and only ever sees the initial user
query, never content from compromised sources**, and a Quarantined LLM that
touches untrusted data but holds no tools. Control flow (the plan) is separated
from data flow (the content). Our envelope **is** the privileged planner's
output, with two additions CaMeL lacks: it is **frozen and signed** as
control-plane data, and it is enforced by a verified runtime monitor with a hard
fallback (the Simplex layer from the design doc).

The deeper reason freezing works is the **Ulysses pact**. Odysseus has himself
bound to the mast before the ship reaches the Sirens, so his later, compromised
self cannot steer toward them. The agent commits to its plan while it is still
uncontaminated (t=0, trusted prompt only); the control plane binds it to that
plan; and after the agent reads untrusted content and its judgment may be
compromised, it is held to the pre-commitment. An injection succeeds only by
making the agent deviate from what it intended before it was exposed, which is
exactly the signal the envelope watches for. Security comes from the freeze and
the trust boundary, not from the plan being provably optimal.

## 4. Grounding: verify the generated plan against the symbolic model

An LLM planner can hallucinate a plan, and a hallucinated envelope is worse than
none. So the generated plan is **verified before it is signed**, exactly as
[Veritas](https://www.sciencedirect.com/science/article/abs/pii/S0306457326002219)
verifies LLM-generated behavior trees for logical consistency (goal reachable)
and factual consistency (aligned with facts) using STRIPS-like operators.

We already have this machine: Phase B's feasibility check is a goal-reachability
test over a tool ontology. Run it on each generated mode. A mode whose plan
cannot actually reach the goal conditions, or that names tools that do not exist,
or whose preconditions are incoherent, is repaired or dropped before signing. The
symbolic ontology is the ground truth that disciplines the LLM's fluency. This is
the neuro-symbolic split: the LLM proposes (broad, fluent, may err), the symbolic
checker disposes (narrow, sound, grounds it).

## 5. Representation: a behavior tree / AND-OR plan

Phases A and B used a linear phase list. The multi-modal envelope needs
branching, so the representation generalizes to a **behavior tree** (equivalently
an AND-OR graph):

- **OR / selector nodes** are the anchor modes (the plausible alternative plans).
- **AND / sequence nodes** are the ordered phases within a mode.
- **loops / decorators** are repeatable phases (read many).
- leaves are typed action classes with preconditions and effects.

Behavior trees are the standard structure for a bounded space of plausible
behaviors in robotics and games, and they carry the goal-reachability semantics
Veritas uses. Conformance is a token replay against the tree: the trace is
in-plan if it is a path through some mode; graded by how many modes it is
consistent with (the MultiPath distribution).

## 6. The generation pipeline (all at t=0, on trusted input)

```
sealed goal + tool schemas + ontology
        │  (privileged planner, sees only the trusted prompt — CaMeL)
        ▼
   sample K candidate plans (self-consistency / temperature)
        │
        ▼
   cluster into anchor modes (MultiPath); frequency = probability
        │
        ▼
   verify each mode against the ontology (Veritas + Phase-B feasibility);
   repair or drop incoherent modes
        │
        ▼
   assemble the behavior tree (OR modes, AND phases)
        │
        ▼
   freeze + sign as control-plane data (mandate / Ulysses pact)
        ▼
              the signed Intent Envelope
```

At runtime the Phase-A/B monitor enforces conformance to this frozen tree, with
the two-signal gate and the feasibility check. If the task legitimately grows,
the control plane **re-clears** it: regenerate and re-sign on trusted input, the
way Air Traffic Control issues a new clearance for a route change rather than
letting the pilot improvise.

## 7. Cross-domain and creative inspirations

Where the engineering fields ran out, fiction and older ideas carried the
intuition, and several earned a real place in the design.

| Source | Idea | Role in generation |
|---|---|---|
| Waymo MultiPath | anchor trajectories; distribution over modes | the envelope is a mixture of plausible plans |
| Scenic / ScenicNL | a probabilistic program over scenarios, from NL | compile the goal into a plan generator, sample it |
| CaMeL (DeepMind) | privileged planner sees only the trusted query | injection-safe generation; control/data split |
| Homer, the Odyssey | the Ulysses pact: bind yourself before the Sirens | freeze the pre-commitment against the future compromised self |
| LLM self-consistency | sample many reasoning paths; keep the recurring | get the mode distribution and its probabilities |
| Veritas / behavior trees | verify goal reachability of a generated BT | ground the LLM plan in the symbolic ontology |
| Air Traffic Control | file a plan, fly the cleared route, re-clear to change | regenerate + re-sign on legitimate scope growth |
| Dune (prescience) | seeing the branching plausible futures | multi-modal future sampling is computing those branches |
| Minority Report | precrime: act before the harmful act completes | feasibility predicts the mission-break before it lands |
| Jazz (the changes) | improvise freely within the harmonic constraints | freedom of action within the fixed modes and goal |
| Heist films | the crew's plan; going off-script is the tell | deviation from the sealed plan is the injection signal |
| Star Trek | filed mission profile; codes for off-profile acts | step-up authorization for consequential deviations |

The load-bearing four are MultiPath (the form of the distribution), CaMeL (safe
generation), the Ulysses pact (why freezing works), and Veritas/feasibility
(grounding the plan). The rest are intuition pumps that confirm the shape.

## 8. Open questions and honest risks

- **Planner fidelity and mode coverage.** If the sampled modes miss a legitimate
  plan, the agent that takes it is escalated, not blocked (two-signal), and can be
  re-cleared. Better to under-generate modes and escalate than to over-block. The
  floor is still the backstop.
- **Cost.** K planner samples plus verification per task is a real seal-time cost.
  It is paid once, off the runtime hot path, and K can be small (even two samples
  give useful consensus).
- **The trusted-planner assumption.** The privileged planner must genuinely see
  only the sealed prompt. If any untrusted content reaches it, the Ulysses pact is
  broken. This is an architectural obligation (CaMeL's control/data split), not a
  soft guideline.
- **Grounding depends on the ontology.** Without tool preconditions/effects, the
  Veritas-style verification degrades to "tools exist and types match," and the
  envelope is a plausible plan that is not reachability-checked. Still useful,
  weaker.
- **Legitimate open-ended tasks.** Some goals are exploratory with no crisp plan.
  There, the envelope is coarse (scope and consequence only), and the statistical
  sensor and budgets carry more weight. We accept a spectrum from tightly-planned
  to loosely-scoped tasks.

## 9. Phased implementation of generation

- **C1 (single grounded mode).** Generate one plan from the sealed prompt (or take
  the ``structured_intent`` we already accept), verify it with Phase-B
  feasibility, sign it. This already gives a real, grounded, signed envelope.
- **C2 (multi-modal).** Sample K plans, cluster into anchor modes with
  probabilities, verify each, assemble the mixture. Conformance becomes
  distributional (track any high-probability mode).
- **C3 (behavior tree + re-clearance).** Full AND-OR behavior-tree representation,
  branch-aware conformance, and the re-clearance loop for scope growth.

## Sources

- Waymo MultiPath and multimodal motion prediction.
- Scenic and ScenicNL: probabilistic scenario programs, incl. from natural language.
- CaMeL (Google DeepMind): dual-LLM privilege separation against prompt injection.
- LLM self-consistency and plan-sample-verify.
- Veritas: verified behavior-tree generation for LLM agents.
- Homer, the Odyssey (the Ulysses pact); the AI-safety pre-commitment framing.
