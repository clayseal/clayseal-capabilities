"""Verifying OIDC provider: accept ANY IdP's JWTs via discovery/JWKS.

Unlike the claim-mapping adapters (which trust the caller to have verified the
credential), this provider does the cryptographic verification itself:
discovery document → JWKS → signature/issuer/audience/expiry checks → a
``binding.v1``-conformant ``AuthorityBinding`` with ``evidence_verified=True``.

Needs the ``[oidc]`` extra (PyJWT + httpx)::

    pip install 'agentauth-capabilities[oidc]'

    provider = VerifyingOidcProvider(
        discovery_url="https://idp.example/.well-known/openid-configuration",
        audience="https://api.mine.example",
    )
    session = provider.verify_session(raw_jwt)          # verified, PoP-agnostic
    # or register it so the rest of the stack resolves it by name:
    register_identity_provider(provider)

Works against AgentAuth's own federation endpoints too
(``/t/{tenant}/.well-known/openid-configuration``) — the stack eats its own
dog food through the same seam a third-party IdP would use.
"""

from __future__ import annotations

import time
from typing import Any

from agentauth.core.authority_binding import AuthorityBinding
from agentauth.core.identity_protocol import CapabilityAuthorizer, IdentitySession

ALLOWED_ALGS = ("RS256", "RS384", "RS512", "ES256", "ES384")


def _require_deps():
    try:
        import httpx  # noqa: F401
        import jwt  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "VerifyingOidcProvider needs PyJWT and httpx. Install with: "
            "pip install 'agentauth-capabilities[oidc]'"
        ) from exc


class VerifyingOidcProvider:
    """IdentityProvider that verifies JWTs against an OIDC discovery document.

    ``jwks``/``issuer`` may be provided statically (offline/test use); otherwise
    they are fetched from ``discovery_url`` and the JWKS is cached for
    ``jwks_ttl_seconds``.
    """

    def __init__(
        self,
        *,
        name: str = "oidc_discovery",
        discovery_url: str | None = None,
        issuer: str | None = None,
        jwks: dict[str, Any] | None = None,
        audience: str | None = None,
        allowed_algs: tuple[str, ...] = ALLOWED_ALGS,
        jwks_ttl_seconds: int = 300,
    ) -> None:
        if discovery_url is None and (issuer is None or jwks is None):
            raise ValueError("provide discovery_url, or both issuer and a static jwks")
        self.name = name
        self.discovery_url = discovery_url
        self.audience = audience
        self.allowed_algs = tuple(allowed_algs)
        self.jwks_ttl_seconds = jwks_ttl_seconds
        self._issuer = issuer
        self._jwks = jwks
        self._jwks_fetched_at = time.monotonic() if jwks is not None else 0.0

    # --- verification ------------------------------------------------------ #
    def _load_discovery(self) -> None:
        _require_deps()
        import httpx

        doc = httpx.get(self.discovery_url, timeout=10.0).raise_for_status().json()
        self._issuer = doc["issuer"]
        jwks_uri = doc["jwks_uri"]
        self._jwks = httpx.get(jwks_uri, timeout=10.0).raise_for_status().json()
        self._jwks_fetched_at = time.monotonic()

    def _current_jwks(self) -> tuple[str, dict[str, Any]]:
        stale = time.monotonic() - self._jwks_fetched_at > self.jwks_ttl_seconds
        if self._jwks is None or (self.discovery_url and stale):
            self._load_discovery()
        return self._issuer, self._jwks

    def verify(self, token: str) -> dict[str, Any]:
        """Verify signature/issuer/audience/expiry → verified claims dict."""
        _require_deps()
        import jwt as pyjwt

        issuer, jwks = self._current_jwks()
        header = pyjwt.get_unverified_header(token)
        if header.get("alg") not in self.allowed_algs:
            raise ValueError(f"token alg {header.get('alg')!r} not in {self.allowed_algs}")
        key = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
        if key is None:
            # one forced refresh handles rotation between cache windows
            if self.discovery_url:
                self._load_discovery()
                _, jwks = self._issuer, self._jwks
                key = next(
                    (k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")),
                    None,
                )
            if key is None:
                raise ValueError(f"no JWKS key matches kid {header.get('kid')!r}")
        public_key = pyjwt.PyJWK(key).key
        return pyjwt.decode(
            token,
            key=public_key,
            algorithms=list(self.allowed_algs),
            issuer=issuer,
            audience=self.audience,
            options={"verify_aud": self.audience is not None},
        )

    # --- IdentityProvider protocol ----------------------------------------- #
    def to_binding(
        self, raw: dict[str, Any] | str, *, evidence_verified: bool = True
    ) -> AuthorityBinding:
        if isinstance(raw, str):
            claims = self.verify(raw)
            evidence_verified = True
        else:
            claims = raw
        return AuthorityBinding.from_verified_credential(
            claims,
            attestation_type="oidc",
            issuer=str(claims.get("iss") or self._issuer or "unknown"),
            evidence_verified=evidence_verified,
        )

    def build_session(
        self,
        raw: dict[str, Any] | str,
        *,
        capability_authorizer: CapabilityAuthorizer | None = None,
        evidence_verified: bool = True,
    ) -> IdentitySession:
        binding = self.to_binding(raw, evidence_verified=evidence_verified)
        return IdentitySession(
            binding=binding,
            provider=self.name,
            capability_authorizer=capability_authorizer,
            raw_credential=raw if isinstance(raw, dict) else {"token": raw},
        )

    def verify_session(
        self,
        token: str,
        *,
        capability_authorizer: CapabilityAuthorizer | None = None,
    ) -> IdentitySession:
        """One-call path: verify a raw JWT and return a verified session."""
        return self.build_session(token, capability_authorizer=capability_authorizer)
