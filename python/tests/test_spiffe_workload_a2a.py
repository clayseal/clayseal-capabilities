"""SPIFFE Workload API live-fetch + A2A AgentCard adapters (Phase 2 completion)."""

from __future__ import annotations

import base64
import json
import sys
import types

import pytest

jwt = pytest.importorskip("jwt")
rfc8785 = pytest.importorskip("rfc8785")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from agentauth.capabilities.identity_adapters import (  # noqa: E402
    A2AAgentCardProvider,
    SpiffeWorkloadProvider,
    get_identity_provider,
    verify_agent_card,
)
from agentauth.capabilities.identity_adapters.a2a_agentcard import (  # noqa: E402
    canonical_card_bytes,
)
from agentauth.core.conformance import check_identity_provider  # noqa: E402
from agentauth.core.schemas import validate_binding  # noqa: E402

# --- SPIFFE Workload API live-fetch ----------------------------------------- #

SPIFFE_ID = "spiffe://prod.example/workload/payments"


class _FakeWorkloadClient:
    """Duck-typed py-spiffe WorkloadApiClient: fetch_jwt_svid(audience=set)."""

    def __init__(self):
        self.requested_audiences: set[str] | None = None

    def fetch_jwt_svid(self, audience: set[str]):
        self.requested_audiences = set(audience)
        return types.SimpleNamespace(
            spiffe_id=SPIFFE_ID,
            token="header.payload.sig",
            claims={
                "sub": SPIFFE_ID,
                "iss": "https://spire.prod.example",
                "aud": sorted(audience),
                "exp": 4102444800,
                "scope": "payments:refund",
            },
        )


def test_workload_provider_live_fetches_and_binds():
    client = _FakeWorkloadClient()
    provider = SpiffeWorkloadProvider(
        audiences={"https://api.mine.example"}, workload_client=client
    )
    session = provider.build_session()
    assert client.requested_audiences == {"https://api.mine.example"}
    binding = session.binding
    assert binding.evidence_verified is True
    assert binding.attestation_type == "spiffe_workload"
    assert binding.subject_id == SPIFFE_ID
    validate_binding(binding.to_dict())
    assert session.raw_credential["token"] == "header.payload.sig"


def test_workload_provider_accepts_preverified_claims_too():
    provider = SpiffeWorkloadProvider(workload_client=_FakeWorkloadClient())
    binding = provider.to_binding({"sub": SPIFFE_ID, "iss": "https://spire.prod.example"})
    assert binding.subject_id == SPIFFE_ID


def test_workload_provider_passes_core_conformance_kit():
    provider = SpiffeWorkloadProvider(workload_client=_FakeWorkloadClient())
    check_identity_provider(
        provider, {"sub": SPIFFE_ID, "iss": "https://spire.prod.example"}
    )


def test_workload_provider_registered_by_name():
    assert isinstance(get_identity_provider("spiffe_workload"), SpiffeWorkloadProvider)


def test_owned_workload_client_is_reused_and_closed(monkeypatch):
    """A client per fetch leaks a gRPC channel each call -- the owned client is
    created once and reused, and close() releases it."""
    created: list = []

    class _FakeOwnedClient:
        def __init__(self, **kwargs):
            created.append(self)
            self.closed = False

        def fetch_jwt_svid(self, audience):
            return types.SimpleNamespace(
                spiffe_id=SPIFFE_ID, token="t", claims={"sub": SPIFFE_ID}
            )

        def close(self):
            self.closed = True

    fake_spiffe = types.ModuleType("spiffe")
    fake_spiffe.WorkloadApiClient = _FakeOwnedClient
    monkeypatch.setitem(sys.modules, "spiffe", fake_spiffe)

    provider = SpiffeWorkloadProvider(audiences={"https://api.mine.example"})
    provider.build_session()
    provider.build_session()
    assert len(created) == 1  # single client reused across fetches
    provider.close()
    assert created[0].closed is True


# --- A2A signed AgentCards --------------------------------------------------- #

KID = "a2a-key-1"


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


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _card() -> dict:
    return {
        "name": "travel-agent",
        "url": "https://agents.example/travel",
        "version": "1.4.0",
        "provider": {"organization": "Example Corp"},
        "skills": [{"id": "book-flight"}, {"id": "book-hotel"}],
    }


def _sign_card(card: dict, private_pem: bytes, *, kid: str = KID, alg: str = "RS256") -> dict:
    protected = _b64url(json.dumps({"alg": alg, "kid": kid}).encode())
    payload = _b64url(rfc8785.dumps({k: v for k, v in card.items() if k != "signatures"}))
    signing_input = f"{protected}.{payload}".encode("ascii")
    alg_obj = jwt.algorithms.get_default_algorithms()[alg]
    signature = alg_obj.sign(signing_input, alg_obj.prepare_key(private_pem))
    return {**card, "signatures": [{"protected": protected, "signature": _b64url(signature)}]}


def test_canonicalization_excludes_signatures(keypair):
    _, private_pem = keypair
    signed = _sign_card(_card(), private_pem)
    assert canonical_card_bytes(signed) == canonical_card_bytes(_card())


def test_signed_card_verifies_and_binds(keypair, jwks):
    _, private_pem = keypair
    signed = _sign_card(_card(), private_pem)
    assert verify_agent_card(signed, jwks=jwks)["kid"] == KID

    provider = A2AAgentCardProvider(jwks=jwks)
    session = provider.build_session(signed)
    binding = session.binding
    assert binding.evidence_verified is True
    assert binding.attestation_type == "a2a_agentcard"
    assert binding.subject_id == "https://agents.example/travel"
    assert set(binding.scope_claims) == {"a2a:book-flight", "a2a:book-hotel"}
    validate_binding(binding.to_dict())


def test_tampered_card_rejected(keypair, jwks):
    _, private_pem = keypair
    signed = _sign_card(_card(), private_pem)
    signed["skills"].append({"id": "transfer-funds"})  # post-signing mutation
    with pytest.raises(ValueError, match="no AgentCard signature verified"):
        verify_agent_card(signed, jwks=jwks)


def test_wrong_key_rejected(keypair):
    _, private_pem = keypair
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(other.public_key()))
    other_jwk["kid"] = KID
    signed = _sign_card(_card(), private_pem)
    with pytest.raises(ValueError, match="no AgentCard signature verified"):
        verify_agent_card(signed, jwks={"keys": [other_jwk]})


def test_unsigned_card_rejected(jwks):
    with pytest.raises(ValueError, match="no signatures"):
        verify_agent_card(_card(), jwks=jwks)


def test_disallowed_alg_rejected(keypair, jwks):
    _, private_pem = keypair
    signed = _sign_card(_card(), private_pem)
    with pytest.raises(ValueError, match="not in"):
        verify_agent_card(signed, jwks=jwks, allowed_algs=("ES256",))


def test_unknown_kid_rejected(keypair, jwks):
    _, private_pem = keypair
    signed = _sign_card(_card(), private_pem, kid="rotated-away")
    with pytest.raises(ValueError, match="no JWKS key matches"):
        verify_agent_card(signed, jwks=jwks)
