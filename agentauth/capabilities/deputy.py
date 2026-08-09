"""Delegation boundary: harm defined by WHO acts.

## The gap this closes

Our measurement splits agent harm by what defines it, and three of the four axes
have an answer. **Target** (where the action points) is contained by scope and
binding. **Volume** (how many) is contained by velocity, measured in
`benchmarks/results/burst.md`. **Sequence** (what data flows) is contained by
`confidentiality.py`, measured in `benchmarks/results/flow.md`. **Content** (what
the action means) is contained by nobody.

There is a fifth question none of them asks: *whose authority was this?*

An agent delegates to a sub-agent. The sub-agent performs an action that is
inside the parent's grant but outside the subset it was delegated. Every field of
the action is correct. The tool was granted, the resource is in scope, the path
is inside the workspace, the arguments match a shape the user authorized, the
pace is ordinary, and nothing sensitive flows. The identical action, performed by
the parent one step earlier, is the task doing its job.

Only the principal is wrong, and no rung of a per-action ladder looks at the
principal. Multi-agent deployment is the dominant 2026 shape and this is its
characteristic failure.

## What the shipped primitive already does, and what it does not

`agentauth.core.delegation` is a delegation-token contract. It gives, and these
hold:

- **Attenuation at issuance.** `issue_delegation` refuses a child capability set
  that is not a subset of the parent's.
- **Transitivity at verify.** `verify_delegation_chain` walks the parent chain
  and re-checks the subset property at every link, so A→B→C cannot exceed A→B
  even if C's token was minted outside `issue_delegation`.
- **Tamper evidence.** A child commits to its parent by hash and ships the
  parent's signed envelope; a rewritten parent breaks the commitment.
- **Expiry.** `is_valid_at` bounds the token's life.

It does not give, and each of these is a way to perform the sub-agent's
overreach with a token that `verify_delegation_chain` returns no violations for:

1. **No actor binding.** `delegate_agent_id` is written into the token, signed,
   and then read by nothing. `verify_delegation_chain` takes no principal
   argument, so a token issued to one sub-agent authorizes every sub-agent, and
   a parent may present its own child's token.
2. **No signer pinning.** `verify_delegation_envelope` verifies the signature
   against the public key carried *inside the signature*. Any party that can
   generate an Ed25519 keypair can mint a root delegation granting itself
   anything and it verifies clean.
3. **No revocation.** Nothing anywhere in the codebase can revoke a delegation.
   `AuthorityTransitionReason.MANUAL_REVOKE` exists in `lineage.py` as a label on
   an audit record, not as a check. A compromised sub-agent holds its authority
   until the token expires.
4. **No root binding.** A chain is checked for internal consistency and never
   against *this task's* authority, so a sub-agent holding a valid delegation
   from an unrelated principal may act inside this session with it. That is the
   confused deputy proper: the parent cannot perform the action, the child can,
   and the child does it on the parent's behalf.
5. **No depth bound.** `depth` is recorded and never compared to anything.
6. **Fail-open on absence.** `verify_delegation_chain(None)` returns `[]`. A
   caller that looks up the delegation for a principal, finds none, and passes
   what it found is told there are no violations.
7. **Leaf-only expiry.** `verify_delegation_chain` checks `is_valid_at` on the
   presented token and on nothing above it, so a fresh leaf hanging off a root
   whose grant has lapsed verifies clean.

Two more were found by the chain-shape sweep in `benchmarks/deputy.py` **after**
this boundary was first written, and both walked through it:

- `depth` is a number a token writes about itself. The first version of this
  module compared `token.depth` to `max_depth` and nothing compared `token.depth`
  to the chain underneath it, so a leaf on a ten-link chain that declared
  `depth: 1` was accepted while the identical chain declared honestly was
  refused. The depth bound is now taken from the presented chain.
- Leaf-only expiry (7 above) was inherited: this boundary called the primitive
  and got the primitive's answer. Validity is now checked over every link.

This module is the verify boundary those six need. It is deliberately a *layer
over* the core primitive rather than a fork of it: every capability, attenuation
and expiry decision still comes from `verify_delegation_chain`, and what is added
here is the part that asks who is holding the token.

## What it costs

Root binding is the expensive one. It says an action inside this session must be
authorized by a chain rooted at this session's authority, so a specialist
sub-agent carrying its own independent grant is refused by default. That is a
real position and not a free one: cross-authority work has to be declared. The
mandate names the other authorities it accepts (`accepted_roots`), which is the
same shape as declassification in `confidentiality.py` — a sealed, pre-execution
declaration that an injected instruction cannot add to.

Absent a policy there is no check, so a deployment that does not delegate behaves
exactly as it did.

Measured in `benchmarks/results/deputy.md`.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from agentauth.core.delegation import (
    DelegationToken,
    delegation_from_envelope,
    verify_delegation_chain,
    verify_delegation_envelope,
)
from agentauth.core.runtime import ActionDescriptor


@dataclass(frozen=True)
class PrincipalVerdict:
    """Ruling on whether *this principal* may perform this operation."""

    allowed: bool
    reason: str
    # Which check decided, so a results table can attribute a block to a rule
    # rather than to "delegation" as a lump.
    rule: str = ""


@dataclass(frozen=True)
class DelegationPolicy:
    """The sealed, pre-execution declaration this boundary enforces.

    ``root_authority`` is the commitment of the delegation this task's mandate
    was issued as. Every chain presented inside the task must terminate there, or
    at an authority the mandate explicitly accepts.

    ``trusted_signers`` are the hex public keys permitted to mint a delegation in
    this deployment. Empty means no trust policy is configured, and this boundary
    then refuses everything rather than accepting self-signed tokens — the same
    stance `signing.verify_bundle_signatures` takes.
    """

    root_authority: str
    trusted_signers: frozenset[str] = frozenset()
    # Other root authorities this mandate accepts. The declassification analogue:
    # cross-authority work is allowed exactly where the sealed mandate named it.
    accepted_roots: frozenset[str] = frozenset()
    # Re-delegation depth. 0 = the root may not delegate at all.
    max_depth: int = 2

    @classmethod
    def from_mandate(cls, mandate: Mapping[str, Any]) -> DelegationPolicy | None:
        """Read the policy out of a mandate, or None when it declares none."""
        raw = mandate.get("delegation")
        if not isinstance(raw, Mapping) or not raw.get("root_authority"):
            return None
        return cls(
            root_authority=str(raw["root_authority"]),
            trusted_signers=frozenset(str(k) for k in raw.get("trusted_signers", ())),
            accepted_roots=frozenset(str(k) for k in raw.get("accepted_roots", ())),
            max_depth=int(raw.get("max_depth", 2)),
        )


def envelope_chain(envelope: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Every envelope from the presented leaf up to its root, leaf first."""
    chain: list[Mapping[str, Any]] = []
    current: Any = envelope
    while isinstance(current, Mapping):
        chain.append(current)
        current = current.get("parent_envelope")
    return chain


def _signer_of(envelope: Mapping[str, Any]) -> str | None:
    signature = envelope.get("signature")
    if not isinstance(signature, Mapping):
        return None
    key = signature.get("public_key")
    return str(key) if isinstance(key, str) else None


def token_chain(token: DelegationToken) -> list[DelegationToken]:
    """Every link from the presented leaf up to its root, leaf first."""
    chain: list[DelegationToken] = []
    current: DelegationToken | None = token
    while current is not None:
        chain.append(current)
        current = current.parent
    return chain




class DelegationBoundary:
    """Per-action ruling on whose authority an action was performed under.

    Stateless except for revocation, which is the one property that has to be
    remembered: a revoked delegation must stop work that is already in flight,
    and that is only observable across actions.
    """

    def __init__(self, policy: DelegationPolicy) -> None:
        self.policy = policy
        self._revoked: set[str] = set()

    # -- revocation ------------------------------------------------------- #
    def revoke(self, delegation_id: Any) -> None:
        """Withdraw a delegation. Takes effect on the delegate's next action."""
        self._revoked.add(str(delegation_id))

    def revoked(self) -> frozenset[str]:
        return frozenset(self._revoked)

    # -- the check -------------------------------------------------------- #
    def authorize(
        self,
        *,
        principal: str,
        resource: str,
        action: str,
        envelope: Mapping[str, Any] | None,
    ) -> PrincipalVerdict:
        """Return whether ``principal`` may perform ``resource:action`` here."""
        # 6. Absence is a denial, not a pass. The shipped primitive returns "no
        #    violations" for a token that is not there.
        if envelope is None:
            return PrincipalVerdict(
                False, f"no delegation presented by {principal!r}", "presented")

        # The core primitive's own checks first: schema, signature, parent
        # commitment, and the parent chain's structure.
        violations = verify_delegation_envelope(envelope, verify_chain=True)
        if violations:
            return PrincipalVerdict(False, violations[0], "envelope")

        # 2. Signer pinning. A valid signature by an unpinned key is a token the
        #    holder minted for themselves.
        pinned = self.policy.trusted_signers
        if not pinned:
            return PrincipalVerdict(
                False, "no trusted signer policy configured", "signer")
        for link in envelope_chain(envelope):
            signer = _signer_of(link)
            if signer not in pinned:
                return PrincipalVerdict(
                    False, "delegation signed by an unpinned key", "signer")

        try:
            token = delegation_from_envelope(envelope)
        except (KeyError, TypeError, ValueError) as exc:  # pragma: no cover
            return PrincipalVerdict(False, f"unreadable delegation: {exc}", "envelope")

        # 1. Actor binding. The token names its delegate; hold the holder to it.
        if str(token.delegate_agent_id) != str(principal):
            return PrincipalVerdict(
                False,
                f"delegation was issued to {token.delegate_agent_id}, "
                f"presented by {principal}",
                "actor",
            )

        chain = token_chain(token)

        # 5. Depth bound, measured on the chain that was actually presented.
        #    `depth` is a number a token writes about itself: it is signed, and
        #    until this check nothing compared it to the links underneath it. A
        #    leaf on a ten-link chain that declared `depth: 1` cleared the bound
        #    while the same chain declared honestly was refused. Requiring the
        #    declared depths to be exactly [n-1 ... 0] pins each link to its real
        #    position and makes the bound below mean something.
        declared = [link.depth for link in chain]
        if declared != list(range(len(chain) - 1, -1, -1)):
            return PrincipalVerdict(
                False,
                f"declared delegation depths {declared} do not match a chain of "
                f"{len(chain)} links",
                "depth",
            )
        if token.depth > self.policy.max_depth:
            return PrincipalVerdict(
                False,
                f"delegation depth {token.depth} exceeds {self.policy.max_depth}",
                "depth",
            )

        # 7. Validity, over the whole chain. `verify_delegation_chain` checks
        #    `is_valid_at` on the leaf only, so a fresh leaf hanging off an
        #    authority whose own grant had lapsed verified clean. A delegation
        #    cannot outlive the authority it derives from.
        now = datetime.now(timezone.utc)
        for link in chain:
            if not link.is_valid_at(now):
                return PrincipalVerdict(
                    False,
                    f"delegation {link.delegation_id} in this chain is expired "
                    f"or not yet valid",
                    "expiry",
                )

        # 4. Root binding. Internal consistency is not enough: the chain has to
        #    terminate at an authority this task's mandate declared.
        root = chain[-1].commitment()
        if root != self.policy.root_authority and root not in self.policy.accepted_roots:
            return PrincipalVerdict(
                False, "delegation chain does not root at this task's authority", "root")

        # 3. Revocation, checked over the whole chain: revoking a parent has to
        #    take everything it issued with it.
        for link in chain:
            if str(link.delegation_id) in self._revoked:
                return PrincipalVerdict(
                    False, f"delegation {link.delegation_id} revoked", "revoked")

        # Capabilities, per-link attenuation and expiry all come from the shipped
        # primitive. Nothing about them is reimplemented here.
        descriptor = ActionDescriptor(action_name=action, resource_type=resource)
        chain_violations = verify_delegation_chain(
            token, action=descriptor, signed_envelope=envelope)
        if chain_violations:
            return PrincipalVerdict(False, chain_violations[0], "capability")

        return PrincipalVerdict(
            True, f"{principal} holds a delegation for {resource}:{action}", "allow")


def shipped_primitive_allows(
    *,
    resource: str,
    action: str,
    envelope: Mapping[str, Any] | None,
    token: DelegationToken | None = None,
) -> bool:
    """What a caller wiring `core.delegation` as documented gets today.

    Present for measurement, not for use. It is the honest "before" column of
    `benchmarks/results/deputy.md`: look up the delegation, hand it and the
    action to `verify_delegation_chain`, and allow when there are no violations.
    """
    if token is None and envelope is not None:
        try:
            token = delegation_from_envelope(envelope)
        except (KeyError, TypeError, ValueError):
            return False
    descriptor = ActionDescriptor(action_name=action, resource_type=resource)
    return not verify_delegation_chain(
        token, action=descriptor, signed_envelope=envelope)


__all__ = [
    "DelegationBoundary",
    "DelegationPolicy",
    "PrincipalVerdict",
    "envelope_chain",
    "shipped_primitive_allows",
    "token_chain",
]
