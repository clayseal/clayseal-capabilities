"""A2A signed AgentCard verification (identity-evidence source).

A2A v1 AgentCards are signed with JWS over the RFC 8785 (JCS) canonical form
of the card *without* its ``signatures`` field: each signature entry carries a
``protected`` JOSE header (b64url JSON, ``alg`` + ``kid``) and a ``signature``
over ``BASE64URL(protected) . BASE64URL(JCS(card))``.

This adapter verifies a signed card against caller-supplied keys and maps the
verified card into a ``binding.v1`` ``AuthorityBinding``, an A2A peer's
identity as evidence, through the same seam as every other provider. Keys must
come from configuration (the peer's published JWKS); an embedded ``jwk`` in
the protected header is self-asserted and deliberately not trusted.

Needs the ``[a2a]`` extra (rfc8785 + PyJWT)::

    pip install 'agentauth-capabilities[a2a]'

    provider = A2AAgentCardProvider(jwks=peer_jwks)
    session = provider.build_session(signed_card)
"""

from __future__ import annotations

import base64
import json
from typing import Any

from agentauth.core.authority_binding import AuthorityBinding
from agentauth.core.identity_protocol import CapabilityAuthorizer, IdentitySession

# The federation-safe JWS families (EdDSA excluded on purpose, see the
# identity-layer crypto matrix; override via allowed_algs when a peer differs).
ALLOWED_ALGS = ("RS256", "RS384", "RS512", "ES256", "ES384", "PS256", "PS384")


def _require_deps():
    try:
        import jwt  # noqa: F401
        import rfc8785  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "A2A AgentCard verification needs rfc8785 and PyJWT. Install with: "
            "pip install 'agentauth-capabilities[a2a]'"
        ) from exc


def _b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def canonical_card_bytes(card: dict[str, Any]) -> bytes:
    """RFC 8785 (JCS) canonicalization of the card minus ``signatures``."""
    _require_deps()
    import rfc8785

    unsigned = {key: value for key, value in card.items() if key != "signatures"}
    return rfc8785.dumps(unsigned)


def verify_agent_card(
    card: dict[str, Any],
    *,
    jwks: dict[str, Any] | None = None,
    public_key: Any | None = None,
    allowed_algs: tuple[str, ...] = ALLOWED_ALGS,
) -> dict[str, Any]:
    """Verify a signed AgentCard; return the protected header that verified.

    Accepts the card as long as at least one ``signatures`` entry verifies with
    the supplied keys (``jwks`` matched by ``kid``, or an explicit
    ``public_key``). Raises ``ValueError`` when unsigned or nothing verifies.
    """
    _require_deps()
    import jwt as pyjwt

    signatures = card.get("signatures") or []
    if not signatures:
        raise ValueError("AgentCard carries no signatures")
    payload_b64 = _b64url_encode(canonical_card_bytes(card))
    algorithms = pyjwt.algorithms.get_default_algorithms()

    failures: list[str] = []
    for entry in signatures:
        try:
            protected_b64 = entry["protected"]
            header = json.loads(_b64url_decode(protected_b64))
            alg = header.get("alg")
            if alg not in allowed_algs:
                raise ValueError(f"alg {alg!r} not in {allowed_algs}")
            key = public_key
            if key is None:
                if jwks is None:
                    raise ValueError("no key source: pass jwks= or public_key=")
                kid = header.get("kid")
                jwk = next(
                    (
                        k
                        for k in jwks.get("keys", [])
                        if kid is None or k.get("kid") == kid
                    ),
                    None,
                )
                if jwk is None:
                    raise ValueError(f"no JWKS key matches kid {kid!r}")
                key = pyjwt.PyJWK(jwk).key
            signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
            signature = _b64url_decode(entry["signature"])
            if not algorithms[alg].verify(signing_input, key, signature):
                raise ValueError("signature mismatch")
            return header
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            failures.append(str(exc))
    raise ValueError(f"no AgentCard signature verified: {'; '.join(failures)}")


def card_to_claims(card: dict[str, Any], header: dict[str, Any]) -> dict[str, Any]:
    """Flatten a verified AgentCard into binding-shaped claims."""
    provider_block = card.get("provider") or {}
    skills = card.get("skills") or []
    return {
        # The card URL is the canonical A2A identifier (binding subject);
        # the human-facing name rides along separately.
        "sub": card.get("url") or card.get("name"),
        "agent_name": card.get("name"),
        "agent_type": "a2a_agent",
        "iss": header.get("iss") or provider_block.get("organization") or "a2a",
        "owner": provider_block.get("organization"),
        "scopes": [
            f"a2a:{skill['id']}" for skill in skills if isinstance(skill, dict) and skill.get("id")
        ],
        "agent_card_version": card.get("version"),
    }


class A2AAgentCardProvider:
    """IdentityProvider accepting A2A signed AgentCards as identity evidence."""

    def __init__(
        self,
        *,
        name: str = "a2a_agentcard",
        jwks: dict[str, Any] | None = None,
        public_key: Any | None = None,
        allowed_algs: tuple[str, ...] = ALLOWED_ALGS,
    ) -> None:
        self.name = name
        self.jwks = jwks
        self.public_key = public_key
        self.allowed_algs = tuple(allowed_algs)

    def verify(self, card: dict[str, Any]) -> dict[str, Any]:
        header = verify_agent_card(
            card,
            jwks=self.jwks,
            public_key=self.public_key,
            allowed_algs=self.allowed_algs,
        )
        return card_to_claims(card, header)

    # --- IdentityProvider protocol ----------------------------------------- #
    def to_binding(
        self, raw: dict[str, Any], *, evidence_verified: bool = False
    ) -> AuthorityBinding:
        """Verify the signed card in ``raw`` and bind it.

        ``evidence_verified`` is ignored on the trusted path: it becomes True
        because verification happens here, or the card is rejected.
        """
        claims = self.verify(raw)
        return AuthorityBinding.from_verified_credential(
            claims,
            attestation_type="a2a_agentcard",
            issuer=str(claims.get("iss")),
            evidence_verified=True,
        )

    def build_session(
        self,
        raw: dict[str, Any],
        *,
        capability_authorizer: CapabilityAuthorizer | None = None,
        evidence_verified: bool = False,
    ) -> IdentitySession:
        return IdentitySession(
            binding=self.to_binding(raw, evidence_verified=evidence_verified),
            provider=self.name,
            capability_authorizer=capability_authorizer,
            raw_credential=raw,
        )
