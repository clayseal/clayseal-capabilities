# Changelog

All notable changes to **agentauth-capabilities** are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.4.0] - 2026-07-05

### Added

- **Cross-provider identity integration** — layer 2 works with five built-in L1 adapters:
  - `agentauth`, `spiffe_jwt`, `oidc`, `auth0`, `aws_sts`
- Shared authority contract in `agentauth.core`:
  - `AuthorityBinding`, `IdentityProvider`, `IdentitySession`, `CapabilityTokenBackend`, `CapabilityLayer`
- `agentauth.capabilities.identity_adapters` registry with `get_identity_provider(name)`.
- `agentauth.capabilities.integration` — `execution_context_from_session`, `default_biscuit_backend()`.
- `AgentAuthCapabilityLayer` in `agentauth.capabilities.layer`.
- `docs/cross_layer_integration.md` and `examples/04_cross_provider_commit.py`.
- `docs/DEV_GUIDE.md` — comprehensive developer guide.
- GitHub Actions CI (installs identity from sibling repo, runs `python/tests`).
- Eight adapter tests in `python/tests/test_identity_adapters.py`.

### Changed

- Depends on `agentauth-identity @ v0.4.0`.
- Removed duplicate `providers/` tree in favor of `identity_adapters/`.

## [0.3.1] - 2026-07-01

### Changed

- Cleanup after split: namespace layout, `.gitignore`, dependency pin to identity v0.3.1.

## [0.3.0] - 2026-06-30

### Added

- Initial standalone release of the capabilities layer (commit tokens, mandates, leases, value budgets).
