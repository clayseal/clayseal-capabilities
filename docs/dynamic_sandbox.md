# The dynamic behavioral sandbox

A runtime containment layer for LLM agents that bounds an agent to the behavior
consistent with its sealed goal, so that a prompt-injected or manipulated agent
cannot act outside what the task authorized. The design goal is a partnership
property: a human can delegate to an agent and trust that no text the agent reads
can turn it against the human's interest, because the authority to act is bound to
the goal, not to the agent's momentary belief about what it was told.

## The paradigm shift

Deployed prompt-injection defenses today are in the recognize-the-attack
paradigm. Detectors classify text as malicious; sanitizers (spotlighting,
delimiting) try to neutralize injected instructions. Both enumerate bad inputs,
both lose to novel phrasings, and both are a permanent arms race.

The dynamic sandbox inverts this. It does not model attacks at all. It models the
goal, derives the set of trajectories consistent with that goal, and rejects any
action that leaves that set. This is a whitelist of goal-consistent behavior
rather than a blacklist of attacks, so it generalizes to attacks never seen. The
same inversion is what let control-flow integrity retire whole exploit classes
without signatures, and what lets Waymo's responsibility-sensitive safety bound a
car's behavior without training on every crash.

## Why it cannot overfit to attacks, and where it still can

The envelope is derived from the goal and the tool semantics. It never reads
attack examples and it is not trained on trajectory data, so it cannot overfit to
an attack distribution the way a learned detector does. That is a real structural
advantage.

The honest residual risk is designer overfitting: a defense tuned to the specific
attacks its author happened to look at. The recipient-binding rule was added after
observing the banking attack. This is why the evaluation protocol below is built
around held-out suites, held-out attack types, and an adaptive adversary. A
defense that only holds where it was tuned is not a safety envelope.

## Architecture: layered containment

The layers run in order at each proposed action, cheapest and most certain first.

1. **Capability floor (membership).** The action's tool, verb, and resource must
   be in the goal-derived scope. This is object-capability security: authority is
   the scope token, not the agent's identity or its belief.

2. **Destination binding (egress).** Any external identifier in the arguments of an
   effect action (recipient IBAN, email, URL, bare host) must be on the authorized
   destination set. One general primitive across financial recipients and network
   destinations. This is what stops a permitted send tool from becoming an exfil
   channel.

3. **Dynamic structural conformance (the partial-order manifold).** The core. The
   plan is a partial order over phases, not a total sequence. Only real precedence
   edges are enforced: causal and precondition order where a domain model exists
   (landmark analysis: build before deploy), and verb-class order everywhere
   (gather before act, an effect before any acquisition is out of order).
   Independent actions interleave freely. This keeps the dynamic structural signal
   while permitting the legitimate variation a real agent shows.

4. **Two-signal danger gate.** A structural deviation is escalated or denied by its
   consequence. An off-plan read steps up for confirmation; an off-plan
   consequential action is denied. This is the immune-system danger model:
   deviation times consequence, not deviation alone.

5. **Statistical sensor (advisory).** Volume and drift patterns (velocity,
   fan-out, structuring, slow drift) that are not structural edges. Demoted to a
   sensor that never blocks alone, because it is the only layer that can overfit
   to trajectory data, and its false positives are highest on sparse traces.

The whole stack sits behind one gateway with a tamper-evident receipt per action,
the runtime-assurance pattern: a verified monitor wrapping an unverified agent.

## What the partial order buys, precisely

A total-order plan rejects legitimate interleavings and destroys utility. Pure
membership throws away the structural signal and becomes a static allowlist. The
partial order is the middle that keeps the security-bearing order and drops the
incidental serialization. The precedence edges are derived from trusted metadata
(verb class) or a formal domain model (landmark analysis), never from model text,
so they are not injectable. Measured on banking, replacing total order with the
partial order raised clean utility from 17% to the 50% baseline while holding
attack success at zero in combination with destination binding.

## Live results so far (AgentDojo, gpt-4o-mini, banking, n=30)

| configuration | clean utility | attack success | utility under attack |
|---------------|--------------:|---------------:|---------------------:|
| no defense | 70% | 67% | 53% |
| full stack (scope + partial-order + binding) | 60% | 0% | 57% |

The full stack holds attack success at zero. Utility under attack is higher with
the defense than without, because the sandbox keeps the agent on task instead of
letting the injection derail it. The 10-point clean-utility gap is residual scope
tightness (minimal scope blocks some benign orientation calls), the next target.

These numbers are on the design suite. They are necessary, not sufficient. The
claim that matters is generalization, below.

## Evaluation protocol (the anti-overfitting contract)

1. **Held-out suites, zero tuning.** Design on banking. Evaluate the same sandbox,
   no per-suite changes, on workspace, travel, and slack. Different ontologies,
   different destinations (emails and URLs, not IBANs).

2. **Held-out attack types.** Design used important_instructions only. Evaluate on
   tool_knowledge, injecagent, ignore_previous, system_message.

3. **Adaptive adversary.** An envelope-aware attacker that knows the defense and
   optimizes to evade it: stay in scope, satisfy verb-class order, mimic the plan.
   Residual attack success against a defense-aware attacker is the decisive number.

4. **Deployable, not oracle.** Replace ground-truth destination seeding with
   provenance: an effect action whose arguments are tainted by untrusted tool
   output rather than by a trusted-named resource is denied. This is the CaMeL
   data-flow direction and the only principled catch for the read-then-send class.

## Known limitations, stated plainly

- **Output manipulation is out of scope.** An injection that only changes what the
  agent says, with no unauthorized tool call, is invisible to an action-gating
  sandbox. Some AgentDojo travel injections are exactly this. The sandbox governs
  actions, not speech.
- **Read-to-attacker resource.** A read of an attacker-controlled URL (SSRF-style)
  is an acquisition, so verb-class order does not flag it and the current egress
  gate covers effect verbs. Extending egress to reads is open work.
- **In-goal wrong-target actions.** When a destructive tool is legitimately in
  scope but aimed at the wrong object (delete the wrong file id), only argument
  binding or provenance separates it from the benign call.
- **Oracle seeding.** The strongest current numbers use ground-truth scope and
  destinations. The deployable system must reach these from the goal and
  provenance. That gap is named, not hidden.
