# AgentAuth Capabilities (layer 2)

Dynamic capability narrowing: Biscuit attenuation (via identity), commit tokens,
delegation, mandates, goal-bound leases, session value budgets.

## Quickstart

```bash
pip install -e ".[dev]"
python examples/03_commit_token.py
```

Depends on [agentauth-core](https://github.com/pberlizov/agentauth-core) v0.5.0+.
The default Biscuit backend also uses [agentauth-identity](https://github.com/pberlizov/agentauth-identity) v0.5.0+.

Import identity types with `from agentauth.identity import AgentAuth` when using this layer alone.

## Cross-provider identity (5 built-in adapters)

Layer 2 works with **any** of these L1 stacks via `get_identity_provider(name)`:

- `agentauth` — native AgentAuth credentials
- `spiffe_jwt` — SPIRE / SPIFFE JWT-SVID
- `oidc` — generic OIDC access tokens
- `auth0` — Auth0 M2M client-credentials
- `aws_sts` — AWS STS / IAM role sessions

See [docs/cross_layer_integration.md](docs/cross_layer_integration.md), [docs/DEV_GUIDE.md](docs/DEV_GUIDE.md), and `examples/04_cross_provider_commit.py`.
