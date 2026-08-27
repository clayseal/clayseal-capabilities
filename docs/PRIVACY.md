# Clay Seal Capabilities Privacy and Data Handling

This document describes data-handling expectations for Clay Seal Capabilities,
the layer that turns verified identity into scoped, verifiable authorization
artifacts. It is developer guidance, not a customer-specific legal privacy
policy.

## Data This Layer Handles

Clay Seal Capabilities may process:

- Verified identity claims and normalized `AuthorityBinding` values.
- Tenant IDs, agent IDs, human or service principals, issuers, and subjects.
- Action names, resource references, scopes, mandates, leases, and budget
  values.
- Input commitment hashes for commit-token binding.
- Commit-token IDs, expiry timestamps, replay-store keys, and verification
  decisions.
- IdP metadata from OIDC, SPIFFE, Auth0, AWS STS, Entra Agent ID, Azure AD, or
  GCP integrations.

This layer should not receive raw secrets or full business payloads when an
input hash, redacted parameter set, or stable reference is enough.

## Secrets

Treat the following as secrets:

- Capability signing keys and KMS credentials.
- Bearer tokens and raw IdP tokens before verification.
- Commit tokens until they expire or are consumed.
- Redis, DynamoDB, database, and IdP client credentials.
- Policy-engine credentials for OPA, Cedar, OpenFGA, or custom evaluators.

## Storage and Retention

Capabilities are designed to be short-lived. Production systems should:

- Keep commit-token TTLs short, usually minutes.
- Use replay-defense stores for multi-instance gateways.
- Expire replay records after the maximum token lifetime plus clock skew.
- Avoid retaining raw action inputs when a commitment hash is sufficient.
- Keep mandate and lease logs only as long as needed for audit or incident
  response.

## Data Minimization

- Bind inputs with canonical hashes instead of storing raw payloads.
- Use coarse resource references where exact object names are sensitive.
- Strip unused IdP claims before building an `IdentitySession`.
- Do not set `evidence_verified=True` unless the upstream verifier checked
  signature, issuer, audience, expiry, and revocation policy where applicable.

## Production Controls

- Pin issuer and audience for live IdP adapters.
- Use HTTPS and explicit host allowlists for remote verification.
- Use Redis or DynamoDB replay defense when more than one gateway instance can
  accept the same commit token.
- Rotate capability signing keys and keep key IDs in emitted artifacts.
- Log denials and verification failures without logging secrets or raw payloads.

## Compatibility and Branding

The product, the distribution, the import root and the CLI are all `clayseal`.
The pre-0.6 `agentauth.*` import paths still resolve with a `DeprecationWarning`
and are removed in 0.7; see [MIGRATION.md](MIGRATION.md).
