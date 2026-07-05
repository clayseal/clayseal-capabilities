# AgentAuth Capabilities (layer 2)

Dynamic capability narrowing: Biscuit attenuation (via identity), commit tokens,
delegation, mandates, goal-bound leases, session value budgets.

## Quickstart

```bash
pip install -e ".[dev]"
python examples/03_commit_token.py
```

Depends on [agentauth-identity](https://github.com/pberlizov/agentauth-identity) v0.3.1+.

Import identity types with `from agentauth.identity import AgentAuth` when using this layer alone.
