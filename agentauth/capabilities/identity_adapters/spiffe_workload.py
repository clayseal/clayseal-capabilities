"""SPIFFE Workload API live-fetch provider.

Where :mod:`spiffe_jwt` maps claims the *caller* already verified, this
provider talks to a running SPIFFE agent (SPIRE, or anything speaking the
Workload API) over its Unix domain socket and fetches a fresh JWT-SVID
itself — the workload never handles long-lived credentials at all.

Needs the ``[spiffe]`` extra (py-spiffe, which brings grpcio)::

    pip install 'agentauth-capabilities[spiffe]'

    provider = SpiffeWorkloadProvider(audiences={"https://api.mine.example"})
    session = provider.build_session()        # live-fetch from the agent

The socket path resolves from ``SPIFFE_ENDPOINT_SOCKET`` (the SPIFFE-standard
variable) when not passed explicitly. The Workload API connection is the trust
boundary — the agent only issues SVIDs to workloads it has attested — so the
returned claims are ``evidence_verified``.
"""

from __future__ import annotations

from typing import Any

from agentauth.core.authority_binding import AuthorityBinding
from agentauth.core.identity_protocol import CapabilityAuthorizer, IdentitySession

from agentauth.capabilities.identity_adapters.spiffe_jwt import claims_from_spiffe_jwt

SOCKET_ENV = "SPIFFE_ENDPOINT_SOCKET"
DEFAULT_AUDIENCE = "agentauth"


class SpiffeWorkloadProvider:
    """IdentityProvider that live-fetches JWT-SVIDs from the SPIFFE Workload API.

    ``workload_client`` is injectable (anything with
    ``fetch_jwt_svid(audience: set) -> svid``); when omitted, a
    ``spiffe.WorkloadApiClient`` is created per fetch against ``socket_path``
    (or ``SPIFFE_ENDPOINT_SOCKET``).
    """

    def __init__(
        self,
        *,
        name: str = "spiffe_workload",
        socket_path: str | None = None,
        audiences: set[str] | list[str] | str | None = None,
        workload_client: Any | None = None,
        timeout: float | None = 10.0,
    ) -> None:
        self.name = name
        self.socket_path = socket_path
        if isinstance(audiences, str):
            audiences = {audiences}
        self.audiences = set(audiences) if audiences else {DEFAULT_AUDIENCE}
        self.workload_client = workload_client
        self.timeout = timeout

    def _fetch(self, audiences: set[str]) -> dict[str, Any]:
        client = self.workload_client
        if client is None:
            try:
                from spiffe import WorkloadApiClient
            except ImportError as exc:  # pragma: no cover
                raise ImportError(
                    "SpiffeWorkloadProvider needs py-spiffe. Install with: "
                    "pip install 'agentauth-capabilities[spiffe]'"
                ) from exc
            client = WorkloadApiClient(
                socket_path=self.socket_path, default_timeout=self.timeout
            )
        svid = client.fetch_jwt_svid(audience=set(audiences))
        claims = dict(svid.claims or {})
        claims.setdefault("sub", str(svid.spiffe_id))
        claims["token"] = svid.token
        return claims

    # --- IdentityProvider protocol ----------------------------------------- #
    def to_binding(
        self,
        raw: dict[str, Any] | None = None,
        *,
        evidence_verified: bool = True,
        audiences: set[str] | None = None,
    ) -> AuthorityBinding:
        """Build a binding; ``raw=None`` live-fetches a fresh SVID first."""
        claims = raw if raw is not None else self._fetch(audiences or self.audiences)
        normalized = claims_from_spiffe_jwt(claims) if "sub" in claims else claims
        return AuthorityBinding.from_verified_credential(
            normalized,
            attestation_type="spiffe_workload",
            issuer=str(claims.get("iss") or "spiffe-workload-api"),
            evidence_verified=evidence_verified,
        )

    def build_session(
        self,
        raw: dict[str, Any] | None = None,
        *,
        capability_authorizer: CapabilityAuthorizer | None = None,
        evidence_verified: bool = True,
        audiences: set[str] | None = None,
    ) -> IdentitySession:
        claims = raw if raw is not None else self._fetch(audiences or self.audiences)
        return IdentitySession(
            binding=self.to_binding(claims, evidence_verified=evidence_verified),
            provider=self.name,
            capability_authorizer=capability_authorizer,
            raw_credential=claims,
        )


provider = SpiffeWorkloadProvider()
