"""Verifying identity adapters: real JWT verification, no network (static JWKS)."""

from __future__ import annotations

import json
import time

import pytest

jwt = pytest.importorskip("jwt")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from clayseal.capabilities.identity_adapters import (
    EntraAgentIdProvider,
    VerifyingOidcProvider,
    is_agent_token,
)
from clayseal.core.conformance import check_identity_provider
from clayseal.core.schemas import validate_binding

ISSUER = "https://idp.test"
AUDIENCE = "https://api.test"
KID = "test-key-1"


@pytest.fixture(scope="module")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return key, private_pem


@pytest.fixture(scope="module")
def jwks(keypair):
    key, _ = keypair
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}


def _mint(private_pem, claims: dict, *, kid: str = KID, alg: str = "RS256") -> str:
    now = int(time.time())
    payload = {"iss": ISSUER, "aud": AUDIENCE, "iat": now, "exp": now + 300, **claims}
    return jwt.encode(payload, private_pem, algorithm=alg, headers={"kid": kid})


@pytest.fixture
def provider(jwks):
    return VerifyingOidcProvider(issuer=ISSUER, jwks=jwks, audience=AUDIENCE)


def test_valid_token_yields_verified_binding(provider, keypair):
    _, private_pem = keypair
    token = _mint(private_pem, {"sub": "agent-1", "scope": "db:read web:*"})
    session = provider.verify_session(token)
    assert session.binding.evidence_verified is True
    assert session.binding.subject_id == "agent-1"
    assert "db:read" in session.binding.capabilities
    assert validate_binding(session.binding.to_dict()) == []


def test_wrong_issuer_rejected(provider, keypair):
    _, private_pem = keypair
    token = jwt.encode(
        {"iss": "https://evil.test", "aud": AUDIENCE, "sub": "x",
         "iat": int(time.time()), "exp": int(time.time()) + 300},
        private_pem, algorithm="RS256", headers={"kid": KID},
    )
    with pytest.raises(jwt.InvalidIssuerError):
        provider.verify(token)


def test_wrong_audience_rejected(provider, keypair):
    _, private_pem = keypair
    token = jwt.encode(
        {"iss": ISSUER, "aud": "https://other.test", "sub": "x",
         "iat": int(time.time()), "exp": int(time.time()) + 300},
        private_pem, algorithm="RS256", headers={"kid": KID},
    )
    with pytest.raises(jwt.InvalidAudienceError):
        provider.verify(token)


def test_unknown_kid_rejected(provider, keypair):
    _, private_pem = keypair
    token = _mint(private_pem, {"sub": "x"}, kid="not-a-real-kid")
    with pytest.raises(ValueError, match="no JWKS key"):
        provider.verify(token)


def test_disallowed_alg_rejected(jwks, keypair):
    _, private_pem = keypair
    strict = VerifyingOidcProvider(
        issuer=ISSUER, jwks=jwks, audience=AUDIENCE, allowed_algs=("ES256",)
    )
    token = _mint(private_pem, {"sub": "x"})
    with pytest.raises(ValueError, match="alg"):
        strict.verify(token)


def test_expired_token_rejected(provider, keypair):
    _, private_pem = keypair
    token = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "x",
         "iat": int(time.time()) - 900, "exp": int(time.time()) - 600},
        private_pem, algorithm="RS256", headers={"kid": KID},
    )
    with pytest.raises(jwt.ExpiredSignatureError):
        provider.verify(token)


def test_provider_passes_conformance_kit(provider):
    samples = [{"sub": "agent-2", "iss": ISSUER, "scope": "db:read"}]
    assert check_identity_provider(provider, samples) == []


def test_audience_is_mandatory(jwks):
    # Verifying signature+issuer without pinning the audience would accept
    # tokens minted for a different relying party -- refuse to construct.
    with pytest.raises(ValueError, match="audience is required"):
        VerifyingOidcProvider(issuer=ISSUER, jwks=jwks)


def test_token_without_exp_rejected(provider, keypair):
    _, private_pem = keypair
    token = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "iat": int(time.time())},  # no exp
        private_pem, algorithm="RS256", headers={"kid": KID},
    )
    with pytest.raises(jwt.MissingRequiredClaimError):
        provider.verify(token)


def test_token_without_iss_rejected(provider, keypair):
    _, private_pem = keypair
    token = jwt.encode(
        {"aud": AUDIENCE, "sub": "x", "iat": int(time.time()), "exp": int(time.time()) + 300},
        private_pem, algorithm="RS256", headers={"kid": KID},
    )
    with pytest.raises(jwt.MissingRequiredClaimError):
        provider.verify(token)


# --- Entra Agent ID ---------------------------------------------------------- #

AGENT_CLAIMS = {
    "sub": "sub-guid",
    "oid": "oid-guid",
    "tid": "tenant-guid",
    "xms_act_fct": "11",
    "xms_par_app_azp": "blueprint-app-guid",
    "scope": "score:read",
}


def test_is_agent_token_gates_on_facets():
    assert is_agent_token(AGENT_CLAIMS)
    assert is_agent_token({"xms_sub_fct": ["13"]})
    assert not is_agent_token({"sub": "human", "xms_act_fct": "1"})


def test_entra_binding_uses_oid_and_records_blueprint(jwks, keypair):
    _, private_pem = keypair
    provider = EntraAgentIdProvider(jwks=jwks, issuer=ISSUER, audience=AUDIENCE)
    token = _mint(private_pem, AGENT_CLAIMS)
    binding = provider.to_binding(token)
    assert binding.subject_id == "oid-guid"
    assert binding.tenant_id == "tenant-guid"
    assert binding.attestation_type == "entra_agent_id"
    assert "entra:blueprint:blueprint-app-guid" in binding.selectors
    assert "entra:facet:11" in binding.selectors
    assert validate_binding(binding.to_dict()) == []


def test_entra_rejects_non_agent_principal(jwks, keypair):
    _, private_pem = keypair
    provider = EntraAgentIdProvider(jwks=jwks, issuer=ISSUER, audience=AUDIENCE)
    human = {k: v for k, v in AGENT_CLAIMS.items() if not k.startswith("xms_")}
    token = _mint(private_pem, human)
    with pytest.raises(ValueError, match="not an Entra AGENT"):
        provider.to_binding(token)


def test_entra_accepts_any_principal_when_configured(jwks, keypair):
    _, private_pem = keypair
    provider = EntraAgentIdProvider(
        jwks=jwks, issuer=ISSUER, audience=AUDIENCE, require_agent=False
    )
    human = {k: v for k, v in AGENT_CLAIMS.items() if not k.startswith("xms_")}
    binding = provider.to_binding(_mint(private_pem, human))
    assert binding.subject_id == "oid-guid"
