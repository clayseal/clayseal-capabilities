# Cross-layer provider integration

Layer 2 and Layer 3 share a **provider-neutral authority contract** so you can swap identity stacks without rewriting capability or receipt logic.

## Shared contract (L2 core)

| Type | Module | Purpose |
|------|--------|---------|
| `AuthorityBinding` | `agentauth.core.authority_binding` | Normalized L1 facts → `AuthorityContext` |
| `IdentitySession` | `agentauth.core.identity_protocol` | Binding + optional capability authorizer |
| `IdentityProvider` | `agentauth.core.identity_protocol` | Maps provider credentials → `AuthorityBinding` |
| `CapabilityTokenBackend` | `agentauth.core.identity_protocol` | Pluggable Biscuit/macaroon attenuation |
| `CapabilityLayer` | `agentauth.core.identity_protocol` | Pluggable L2 surface for L3 |

## Built-in L1 adapters (5 common stacks)

| Provider | `get_identity_provider(...)` | Typical source |
|----------|------------------------------|----------------|
| Clay Seal | `agentauth` | `Credential.to_binding_dict()` |
| SPIFFE / SPIRE | `spiffe_jwt` | JWT-SVID (`sub: spiffe://…`) |
| Generic OIDC | `oidc` | OAuth2 access token claims |
| Auth0 M2M | `auth0` | Client-credentials JWT |
| AWS STS / IAM | `aws_sts` | GetCallerIdentity or web-identity JWT |

## Layer 2 example (any provider → commit token)

```python
from agentauth.capabilities.identity_adapters import get_identity_provider
from agentauth.capabilities.integration import execution_context_from_session
from agentauth.capabilities.commit import issue_commit_token, verify_commit_token
from agentauth.core.signing import generate_keypair

claims = {"sub": "spiffe://example.org/…", "iss": "spiffe://example.org", "scope": "payroll:write"}
session = get_identity_provider("spiffe_jwt").build_session(claims)
ctx = execution_context_from_session(session, action_name="mcp.tools/call/pay", resource_ref="hr:pay", input={"amount": 100})
signed = issue_commit_token(ctx, key=generate_keypair(), ttl_seconds=300)
```

Run: `python examples/04_cross_provider_commit.py`

## Layer 3 example (any provider → receipts)

```python
from agentauth.capabilities.identity_adapters import get_identity_provider
from agentauth.receipts import Policy
from agentauth.receipts.integration import wrap_with_identity_session

session = get_identity_provider("oidc").build_session({...})
wrapper = wrap_with_identity_session(model, Policy.from_yaml("policies/fraud_decision.yaml"), session, mode="shadow")
result = wrapper.run({"transaction_id": "t1"})
```

## Adding a custom L1 provider

```python
from agentauth.capabilities.identity_adapters.registry import register_identity_provider
from agentauth.core.authority_binding import AuthorityBinding

class MyProvider:
    name = "my_idp"
    def to_binding(self, raw, *, evidence_verified=True):
        return AuthorityBinding.from_verified_credential(raw, attestation_type="my_idp", evidence_verified=evidence_verified)
    def build_session(self, raw, *, capability_authorizer=None, evidence_verified=True):
        ...

register_identity_provider(MyProvider())
```

Only set `evidence_verified=True` after cryptographic verification of the upstream credential.
