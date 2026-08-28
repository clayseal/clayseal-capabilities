"""Shared contracts the three layers agree on.

`clayseal.core` is the vocabulary, not the enforcement. It holds the types a
decision is made of — the action, the authority context, the outcome, the
signing primitives — and nothing that decides anything. The capability layer
(`clayseal.capabilities`) enforces; the identity and receipts layers are separate
distributions that read the same types back.

That split is why this is a package rather than a module: a receipt verifier has
to reconstruct what a gateway decided without importing the gateway, so the
things they both name live below both of them.
"""
from clayseal.core.decision import DecisionResult
from clayseal.core.hash_util import hash_canonical_json, sha256_hex
from clayseal.core.outcomes import DecisionOutcome
from clayseal.core.runtime import (
    ActionDescriptor,
    AuthorityContext,
    ExecutionContext,
    SideEffectLevel,
)
from clayseal.core.signing import (
    SigningKey,
    generate_keypair,
    load_or_create_key,
    sign_bundle,
    verify,
)

__all__ = [
    "ActionDescriptor",
    "AuthorityContext",
    "DecisionOutcome",
    "DecisionResult",
    "ExecutionContext",
    "SideEffectLevel",
    "SigningKey",
    "generate_keypair",
    "hash_canonical_json",
    "load_or_create_key",
    "sha256_hex",
    "sign_bundle",
    "verify",
]
