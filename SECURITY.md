# Security policy

## Reporting a vulnerability

Report privately through [GitHub Security
Advisories](https://github.com/clayseal/clayseal-capabilities/security/advisories/new).
Please do not open a public issue for anything that would let an agent get past
a control.

We will acknowledge within 3 working days and give an assessment within 10. If we
disagree that a report is a vulnerability, we will say why in the advisory rather
than closing it silently, because the disagreement is usually about the trust
boundary and that is worth writing down.

## What counts as a vulnerability here

This is a defense-in-depth layer with a stated threat model, so the boundary
matters more than the severity. Read
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) first.

**In scope.** Anything that makes a control fail to apply while reporting
success. Specifically:

- A gate that allows an action it should refuse: an argument encoding the floor
  does not normalize, a path that escapes the scope, a destination that passes
  the egress check, a budget that fails to accumulate.
- A signed object accepted from a signer that was not pinned, or a signature
  check that can be skipped by configuration.
- A replayed commit token, or a token whose binding survives an argument change.
- A denial that the audit trail records as an allow, or a decision missing from
  the hash chain.
- A step-up approval applied without a valid signature, or bound to a different
  request than the one it approves.
- Anything reachable through the MCP proxy that reaches the upstream server
  without passing `authorize()`.
- Resource exhaustion on the authorization path that an attacker can trigger,
  including one that holds a session lock.

**Out of scope, and load-bearing.** These are stated as out of scope in the
threat model rather than being things we have not thought about:

- A compromised control plane. If the process that mints commit tokens and seals
  envelopes is owned, this layer authorizes whatever it says. Layer 2 is an
  enforcement point, not a root of trust.
- A compromised host, or the model provider itself.
- The correctness of the policy. A policy that grants too much is a policy bug,
  and `clayseal policy lint` exists to surface those. A document that grants what
  it says it grants is working as intended.
- **In-scope staging.** Reading a secret-classed object inside the grant and
  writing its content to a publication-classed object inside the same grant. This
  is a known open gap, measured and published in
  [benchmarks/results/in_scope_exfiltration.md](benchmarks/results/in_scope_exfiltration.md).
  Reports of new instances of this class are welcome and will be treated as
  research rather than as an advisory, unless they get past the confidentiality
  flow tracker in a way the published result does not already cover.
- The behaviour of the advisory tiers. The entailment judge and the trajectory
  detector fail open by design and can only escalate, never authorize. Making one
  of them return nothing is not a bypass. Making one of them cause an ALLOW that
  the floor refused is.

## Supported versions

The most recent minor release. This project is pre-1.0, so fixes land on `main`
and in the next release rather than being backported.

## Our own disclosures

Two classes of finding are already public and were found by writing the threat
model rather than by an external report:

- The intent envelope accepted any keyholder when `trusted_keys` was unset, and
  the envelope is the object `reclear` swaps mid-session.
- The step-up approval honoured `CLAYSEAL_STEP_UP_ALLOW_UNSIGNED=1`, so one
  environment variable turned a refusal into a grant.

Both are fixed and both are in [CHANGELOG.md](CHANGELOG.md). We publish these
rather than quietly patching them, and we would rather receive a report in the
same spirit.
