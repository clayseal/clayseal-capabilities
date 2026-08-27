"""The two defects `benchmarks/stress_identity.py` found, pinned.

Both are the shape every other fuzzer in this repository has found: a control
that stops applying when its input does not match what it expected, and reports
success.
"""
import pytest

from agentauth.capabilities.identity_adapters import (
    auth0,
    aws_sts,
    azure_ad,
    gcp,
    oidc,
    spiffe_jwt,
)
from agentauth.capabilities.identity_adapters._claims import (
    AUTHORITY_FIELDS,
    strip_authority_fields,
)
from agentauth.capabilities.principal_ledger import principal_key

#: The three adapters whose normalizer is conditional, so the `else` branch put
#: the caller's dict straight into the binding constructor.
PASSTHROUGH = [("oidc", oidc.provider), ("auth0", auth0.provider),
               ("spiffe_jwt", spiffe_jwt.provider)]
ALL = PASSTHROUGH + [("azure_ad", azure_ad.provider),
                     ("aws_sts", aws_sts.provider), ("gcp", gcp.provider)]

#: SPIFFE is excluded from the cross-issuer tests, and the reason is a point in
#: its favour rather than an exemption: a SPIFFE ID is
#: `spiffe://<trust-domain>/<path>`, so the trust domain is inside the subject
#: and two domains cannot produce the same one. It is the only adapter here whose
#: subject is issuer-qualified by construction, and it enforces that, it refuses
#: a bare `sub` outright. Every other adapter takes an opaque `sub` that is
#: unique only within its issuer.
CROSS_ISSUER = [(n, p) for n, p in ALL if n != "spiffe_jwt"]

#: Shaped to MISS every adapter's normalizer guard: no `sub`, no `auth0.com`
#: issuer. That is what selects the passthrough branch.
FORGED = {
    "subject_id": "alice",
    "iss": "https://evil.example",
    "capabilities": ["payments.transfer:*"],
    "has_capability_grant": True,
    "trust_tier": "hardware",
    "evidence_verified": True,
}


@pytest.mark.parametrize("name,provider", PASSTHROUGH)
def test_claims_cannot_assert_their_own_capabilities(name, provider):
    """A claims dict is who, never what-you-may-do.

    Before the fix this returned a binding carrying `payments.transfer:*` with
    `has_capability_grant=True`, from a dict with no signature over it at all.
    """
    binding = provider.to_binding(dict(FORGED))
    assert not binding.capabilities, f"{name} took capabilities from claims"
    assert not binding.has_capability_grant
    assert not binding.evidence_verified


@pytest.mark.parametrize("name,provider", PASSTHROUGH)
def test_the_passthrough_still_carries_identity(name, provider):
    """The fix must strip authority without breaking the legitimate use.

    The fallback exists for callers holding an already-normalized record, and
    stripping identity too would make it useless rather than safe.
    """
    binding = provider.to_binding({"subject_id": "alice",
                                   "iss": "https://good.example",
                                   "tenant_id": "t1"})
    assert binding.subject_id == "alice"


def test_strip_is_total_on_a_non_mapping():
    # A control that raises on absurd input is the defect class this repository
    # keeps finding; the strip runs on the authorization path.
    assert strip_authority_fields(None) == {}
    assert strip_authority_fields(["not", "a", "mapping"]) == {}


def test_every_authority_field_is_actually_stripped():
    raw = {"subject_id": "a"} | {f: "x" for f in AUTHORITY_FIELDS}
    kept = strip_authority_fields(raw)
    assert set(kept) == {"subject_id"}


# --------------------------------------------------------------------------- #
# Principal identity
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name,provider", CROSS_ISSUER)
def test_subject_id_alone_collides_across_issuers(name, provider):
    """Pinned as a FACT about the adapters, not as an aspiration.

    `sub` is unique only within an issuer, so an adapter reporting it unqualified
    is behaving correctly. This test exists so that anyone reaching for
    `subject_id` as a ledger key sees, in a test name, why they must not.
    """
    a = provider.to_binding({"sub": "alice", "iss": "https://good.example"})
    b = provider.to_binding({"sub": "alice", "iss": "https://evil.example"})
    assert a.subject_id == b.subject_id


@pytest.mark.parametrize("name,provider", CROSS_ISSUER)
def test_principal_key_does_not_collide_across_issuers(name, provider):
    a = provider.to_binding({"sub": "alice", "iss": "https://good.example"})
    b = provider.to_binding({"sub": "alice", "iss": "https://evil.example"})
    assert principal_key(a) != principal_key(b)


def test_principal_key_is_injective_under_a_chosen_sub():
    """A delimiter-joined key is forgeable; a length-prefixed one is not.

    `sub` is attacker-chosen at their own issuer, so under `f"{iss}|{sub}"` the
    value `"|https://good.example|alice"` spells another principal's key.
    """
    good = oidc.provider.to_binding({"sub": "alice",
                                     "iss": "https://good.example"})
    forged = oidc.provider.to_binding(
        {"sub": "https://good.example5:alice", "iss": "https://x"})
    assert principal_key(forged) != principal_key(good)


def test_principal_key_is_stable_under_irrelevant_claims():
    """Instability would split the ledger, which is the session-restart escape
    reappearing one layer down where the principal ledger cannot see it."""
    base = {"sub": "alice", "iss": "https://good.example"}
    a = oidc.provider.to_binding(base)
    b = oidc.provider.to_binding({**base, "scope": "read write", "exp": 999})
    assert principal_key(a) == principal_key(b)


def test_principal_key_refuses_an_unidentified_binding():
    class _Anon:
        issuer = "https://good.example"
        subject_id = ""

    with pytest.raises(ValueError, match="subject_id"):
        principal_key(_Anon())
