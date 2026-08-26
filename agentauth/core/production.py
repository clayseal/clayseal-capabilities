"""Shared production guardrails for Clay Seal runtimes."""

from __future__ import annotations

import os

from agentauth.core.signing import (
    TRUSTED_SIGNER_KEY_IDS_ENV,
    TRUSTED_SIGNER_PUBLIC_KEYS_ENV,
    trusted_signer_policy_from_env,
)

_PRODUCTION_VALUES = frozenset({"production", "prod"})

# The values that RELAX the enforcement posture. Everything else, including an
# unset environment, is treated as production by `fail_closed()` below.
_DEVELOPMENT_VALUES = frozenset({"development", "dev", "test", "testing", "local"})

# Truthy in production => refuse startup.
_IDENTITY_PRODUCTION_DENY = (
    "AGENTAUTH_ALLOW_REMOTE_DEV_ATTESTOR",
    "AGENTAUTH_DEV_ATTESTOR",
)

_RECEIPTS_PRODUCTION_DENY = (
    *_IDENTITY_PRODUCTION_DENY,
    "AGENT_RECEIPTS_ALLOW_STUB",
    "AGENT_RECEIPTS_ALLOW_UNSIGNED_CERTIFICATE",
    "AGENT_RECEIPTS_ALLOW_UNSIGNED_CHECKPOINT",
)

_ATTESTATION_JWKS_ENV = "AGENTAUTH_ATTESTATION_JWKS_URL"
_ATTESTATION_ISSUER_ENV = "AGENTAUTH_ATTESTATION_ISSUER"
_ATTESTATION_AUDIENCE_ENV = "AGENTAUTH_ATTESTATION_AUDIENCE"
_HTTP_ALLOWED_HOSTS_ENV = "AGENTAUTH_HTTP_ALLOWED_HOSTS"


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def deployment_env() -> str:
    return (
        os.environ.get("AGENT_RECEIPTS_ENV", "").strip().lower()
        or os.environ.get("AGENTAUTH_ENV", "").strip().lower()
    )


def is_production() -> bool:
    """True when the deployment NAMES itself production.

    This gates the service startup checks in `production_violations`, which
    demand things a library user does not have (an admin API key, a CORS
    allow-list, a receipts verifier key). It stays opt-in for that reason: a
    process that imports this package must not refuse to start because it did
    not set six environment variables it has no use for.

    For the enforcement posture, use `fail_closed()` instead.
    """
    return deployment_env() in _PRODUCTION_VALUES


def is_development() -> bool:
    """True only when the deployment explicitly names itself non-production."""
    return deployment_env() in _DEVELOPMENT_VALUES


def fail_closed() -> bool:
    """Whether the authorization guards refuse when their input is missing.

    True unless the environment explicitly says `development`. The polarity used
    to be the other way around: every guard asked `is_production()`, so an unset
    variable meant an unpinned commit-token minting key was accepted, a missing
    replay store was accepted, and an intent envelope signed by any keyholder was
    accepted. Documentation said to set the variable. Documentation is not a
    control, and the deployments that most need these guards are exactly the ones
    that never read that line.

    The relaxed path now has to be asked for by name, and it says so once per
    process so a development setting cannot ride into production silently.
    """
    if is_development():
        _warn_relaxed_once()
        return False
    return True


_warned = False


def _warn_relaxed_once() -> None:
    global _warned
    if _warned:
        return
    _warned = True
    import warnings

    warnings.warn(
        f"Clay Seal is running with the enforcement guards relaxed because "
        f"AGENTAUTH_ENV={deployment_env()!r}. Unpinned commit-token minting "
        f"keys, a missing replay store, an unsigned step-up approval and an "
        f"unpinned intent envelope are all accepted in this mode. Unset the "
        f"variable, or set it to 'production', before deploying.",
        RuntimeWarning,
        stacklevel=3,
    )


def reset_relaxed_warning() -> None:
    """Re-arm the one-shot warning. For tests that assert it fires."""
    global _warned
    _warned = False


def production_violations(*, layer: str = "all") -> list[str]:
    """Return human-readable production policy violations for ``layer``.

    ``layer`` is one of ``identity``, ``receipts``, or ``all``.
    """
    if not is_production():
        return []

    violations: list[str] = []

    if layer in {"identity", "all"}:
        for name in _IDENTITY_PRODUCTION_DENY:
            if _env_truthy(name):
                violations.append(f"{name}={os.environ.get(name)}")
        if not os.environ.get("AGENTAUTH_ADMIN_API_KEY", "").strip():
            violations.append("AGENTAUTH_ADMIN_API_KEY is unset")
        cors = os.environ.get("AGENTAUTH_CORS_ORIGINS", "").strip()
        if not cors:
            violations.append("AGENTAUTH_CORS_ORIGINS must be set in production")
        elif "*" in cors.split(","):
            violations.append("AGENTAUTH_CORS_ORIGINS must not include '*' in production")

    if layer in {"receipts", "all"}:
        for name in _RECEIPTS_PRODUCTION_DENY:
            if _env_truthy(name):
                violations.append(f"{name}={os.environ.get(name)}")
        if not os.environ.get("AGENT_RECEIPTS_VERIFIER_API_KEY", "").strip():
            violations.append("AGENT_RECEIPTS_VERIFIER_API_KEY is unset")
        if not _env_truthy("AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES"):
            violations.append(
                "AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES must be set to 1 in production"
            )
        policy = trusted_signer_policy_from_env()
        if not policy.get("public_keys") and not policy.get("key_ids"):
            violations.append(
                f"configure {TRUSTED_SIGNER_PUBLIC_KEYS_ENV} or {TRUSTED_SIGNER_KEY_IDS_ENV} "
                "so receipt verification pins trusted signers"
            )

    if layer in {"identity", "receipts", "all"}:
        if not os.environ.get(_HTTP_ALLOWED_HOSTS_ENV, "").strip():
            violations.append(
                f"{_HTTP_ALLOWED_HOSTS_ENV} must be set in production for outbound HTTP fetches"
            )
        commit_store = os.environ.get("AGENTAUTH_COMMIT_TOKEN_STORE", "").strip().lower()
        if commit_store in {"redis", "rediss"} and not os.environ.get(
            "AGENTAUTH_COMMIT_TOKEN_REDIS_URL", ""
        ).strip():
            violations.append(
                "AGENTAUTH_COMMIT_TOKEN_REDIS_URL is required when AGENTAUTH_COMMIT_TOKEN_STORE=redis"
            )
        jwks_url = os.environ.get(_ATTESTATION_JWKS_ENV, "").strip()
        if jwks_url:
            if not os.environ.get(_ATTESTATION_ISSUER_ENV, "").strip():
                violations.append(
                    f"{_ATTESTATION_ISSUER_ENV} is required when {_ATTESTATION_JWKS_ENV} is set"
                )
            if not os.environ.get(_ATTESTATION_AUDIENCE_ENV, "").strip():
                violations.append(
                    f"{_ATTESTATION_AUDIENCE_ENV} is required when {_ATTESTATION_JWKS_ENV} is set"
                )

    return violations


def enforce_production_policy(*, layer: str = "all") -> None:
    violations = production_violations(layer=layer)
    if violations:
        raise RuntimeError(
            "production deployment refused to start: " + "; ".join(sorted(violations))
        )


def refuse_dev_attestation_client(*, dev_attestation_enabled: bool) -> None:
    """SDK entrypoints call this when dev attestation is requested."""
    if is_production() and dev_attestation_enabled:
        raise RuntimeError(
            "dev_attestation is not permitted when AGENTAUTH_ENV=production; "
            "use a real attestation path or a non-production environment"
        )
    if is_production() and _env_truthy("AGENTAUTH_ALLOW_REMOTE_DEV_ATTESTOR"):
        raise RuntimeError(
            "AGENTAUTH_ALLOW_REMOTE_DEV_ATTESTOR must be unset in production"
        )
