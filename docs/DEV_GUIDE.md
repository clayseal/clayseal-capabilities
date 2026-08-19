# Developer guide — Clay Seal Capabilities (Layer 2)

This guide explains how to **use and operate** the capabilities layer: dynamic, attenuated authorization that sits between identity (layer 1) and verifiable receipts (layer 3). Read it end-to-end if you are wiring Clay Seal into an agent runtime, an MCP gateway, or an enterprise IdP you already run.

---

## What problem this layer solves

Layer 1 answers *who* is acting. Real agent systems also need to answer:

- May this agent **commit** this specific action (file write, API call, payment)?
- Can a sub-agent receive **strictly narrower** rights than its parent?
- How do we enforce **mandates** and **budgets** without calling home on every tool invocation?

**Clay Seal Capabilities** implements that middle layer. Its package name is
still `agentauth-capabilities`, and its Python namespace is still
`agentauth.capabilities`, but the product name developers and customers should
see is Clay Seal. It takes verified identity facts and produces
**action-scoped capability artifacts** — commit tokens, leases, attenuated
Biscuits — that verifiers and runtimes can check offline.

Without this layer, you either over-trust the agent’s static IAM role or under-protect individual tool calls. With it, authorization becomes **per-action, per-resource, and cryptographically constrained**.

---

## Position in the stack

```
┌─────────────────────────────────────────┐
│  L3 agentauth-receipts                  │
│  Receipts, audit, MCP gateway, verify   │
└─────────────────┬───────────────────────┘
                  │ IdentitySession, CapabilityLayer
┌─────────────────▼───────────────────────┐
│  L2 agentauth-capabilities  ← YOU ARE HERE │
│  Commit tokens, mandates, leases, budgets │
└─────────────────┬───────────────────────┘
                  │ AuthorityBinding, verified L1 claims
┌─────────────────▼───────────────────────┐
│  L1 agentauth-identity                  │
│  JWT-SVID, Biscuit, PoP, identity svc   │
└─────────────────────────────────────────┘
```

**Dependency rule:** this repo requires [agentauth-core](https://github.com/pberlizov/clay-seal-core) installed at a **matching tag** (currently `v0.5.0`). The default Biscuit backend also requires [agentauth-identity](https://github.com/pberlizov/clayseal-identity) at the same tag.

**Import convention:**

```python
from agentauth.identity import AgentAuth          # from layer 1
from agentauth.capabilities.commit import issue_commit_token
from agentauth.capabilities.identity_adapters import get_identity_provider
```

There is no top-level `from agentauth import …` in this repo alone.

---

## Installation

### Standard install (pinned)

```bash
pip install "git+https://github.com/pberlizov/clayseal-identity.git@v0.5.0"
pip install "git+https://github.com/pberlizov/clay-seal-core.git@v0.5.0"
pip install "git+https://github.com/pberlizov/clay-seal-capabilities.git@v0.5.0"
```

### Editable development

```bash
git clone https://github.com/pberlizov/clayseal-identity.git ../clayseal-identity
git clone https://github.com/pberlizov/clay-seal-core.git ../clay-seal-core
git clone https://github.com/pberlizov/clay-seal-capabilities.git
cd clay-seal-capabilities
python -m venv .venv && source .venv/bin/activate
pip install -e "../clay-seal-core[dev]"
pip install -e "../clayseal-identity[dev]"
pip install -e ".[dev]"
```

### Verify

```bash
pytest python/tests -q
python examples/03_commit_token.py
python examples/04_cross_provider_commit.py
```

---

## Core concepts

### AuthorityBinding

Defined in `agentauth.core.authority_binding` (shipped from this repo’s `agentauth.core` package, shared conceptually with L1/L3). It is the **normalized output of layer 1 verification**:

- SPIFFE/OIDC subject and issuer
- Attestation type (`agentauth`, `spiffe_jwt`, `oidc`, …)
- Whether evidence was cryptographically verified
- Optional capability authorizer hooks

Upper layers should not parse raw JWTs themselves; they consume `AuthorityBinding` or `IdentitySession`.

### IdentitySession

An `IdentitySession` pairs a binding with optional **capability authorizer** state (e.g. Biscuit root token). It is the object you pass into commit-token issuance or into layer 3’s `wrap_with_identity_session`.

### Commit tokens

A **commit token** is a signed, TTL-bound approval for one logical action:

- Action name (e.g. `mcp.tools/call`, `git.commit`)
- Resource reference (repo path, API resource id)
- Input commitment hash (optional but recommended)
- Authority context copied from L1

Issue with `issue_commit_token`, verify with `verify_commit_token`. Tokens are meant to be checked **immediately before** side effects.

### Mandates, leases, and budgets

Higher-level constructs (see module docstrings and examples):

- **Mandates** — signed task descriptions that bound what an agent session may do.
- **Leases** — time- and scope-bounded capability containers for sandboxes.
- **Value budgets** — numeric limits (e.g. dollar amount, token count) enforced across a session.

Layer 3’s sandbox builder consumes these; layer 2 owns the primitives.

### CapabilityTokenBackend

Pluggable attenuation (default: Biscuit). Lets you swap macaroon-style backends if needed without changing commit-token APIs.

---

## Day-to-day operations

### Native Clay Seal path (L1 + L2)

The common case when you control both identity and capabilities:

```python
from agentauth.identity import AgentAuth
from agentauth.capabilities.integration import execution_context_from_session
from agentauth.capabilities.commit import (
    InMemoryUsedTokenStore,
    issue_commit_token,
    verify_commit_token,
)
from agentauth.core.signing import generate_keypair

auth = AgentAuth(trust_domain="example.org")
agent = auth.register_agent("bots/payment-agent")
credential = auth.identify(agent, principal="finance-bot@example.org", ttl_seconds=600)

session = auth.session(credential).wrap()  # or build via adapter below
# Prefer adapter for symmetry with cross-provider code:
from agentauth.capabilities.identity_adapters import get_identity_provider
identity_session = get_identity_provider("agentauth").build_session(
    credential.to_binding_dict()
)

ctx = execution_context_from_session(
    identity_session,
    action_name="mcp.tools/call/transfer",
    resource_ref="account:payroll",
    input={"amount": 100},
)

signing_key = generate_keypair()
signed = issue_commit_token(ctx, key=signing_key, ttl_seconds=300)

ok, reason = verify_commit_token(
    signed,
    ctx=ctx,
    trusted_minting_keys={signing_key.public_key_hex},
    used_token_store=InMemoryUsedTokenStore(),
)
assert ok, reason
```

`verify_commit_token` returns `(ok, reason)` and never raises: the token is
attacker-reachable input, so the boundary is total by contract. It re-derives
`tool_name`, `resource_ref` and `arguments_hash` from the `ctx` you pass, which
is what makes a mutated argument invalidate the authorization.

`issue_commit_token` is the opposite contract — there is no "no" to return, so a
malformed context raises `ValueError`.

Run the full script: `python examples/03_commit_token.py`.

### Cross-provider path

You **do not** need Clay Seal Identity if you already have one of the supported
stacks:

| Provider name | Typical source |
|---------------|----------------|
| `agentauth` | Native Clay Seal credential |
| `spiffe_jwt` | SPIRE / SPIFFE JWT-SVID |
| `oidc` | Generic OAuth2 access token claims |
| `auth0` | Auth0 M2M JWT |
| `aws_sts` | AWS STS / IAM session |
| `entra_agent_id` | Microsoft Entra Agent ID |
| `azure_ad` | Azure AD workload identity |
| `gcp` | Google Cloud service account / workload identity |

Example with SPIFFE:

```python
from agentauth.capabilities.identity_adapters import get_identity_provider
from agentauth.capabilities.integration import execution_context_from_session
from agentauth.capabilities.commit import (
    InMemoryUsedTokenStore,
    issue_commit_token,
    verify_commit_token,
)
from agentauth.core.signing import generate_keypair

claims = {
    "sub": "spiffe://example.org/agent/payroll",
    "iss": "spiffe://example.org",
    "scope": "payroll:write",
}
session = get_identity_provider("spiffe_jwt").build_session(claims)
ctx = execution_context_from_session(
    session,
    action_name="mcp.tools/call/pay",
    resource_ref="hr:payroll",
    input={"amount": 100},
)
signed = issue_commit_token(ctx, key=generate_keypair(), ttl_seconds=300)
```

**Important:** adapters accept claim dicts for development and testing. In production, set `evidence_verified=True` only after **your** IdP verification path has validated the token signature, audience, and expiry.

Full walkthrough: `python examples/04_cross_provider_commit.py`.

Detailed architecture: [docs/cross_layer_integration.md](cross_layer_integration.md).

---

## Integrating with layer 3 (receipts)

Layer 3 imports the same abstractions. Typical pattern:

```python
from agentauth.capabilities.identity_adapters import get_identity_provider
from agentauth.receipts import Policy
from agentauth.receipts.integration import wrap_with_identity_session

session = get_identity_provider("oidc").build_session(verified_claims)
wrapper = wrap_with_identity_session(
    model,
    Policy.from_yaml("policies/fraud_decision.yaml"),
    session,
    mode="shadow",  # or "bounded_auto" for enforcement
)
result = wrapper.run({"transaction_id": "t1"})
```

Install [agentauth-receipts](https://github.com/pberlizov/clay-seal-receipts) at the matching tag when running this code.

---

## Adding a custom identity provider

When your IdP is not one of the five built-ins:

```python
from agentauth.capabilities.identity_adapters.registry import register_identity_provider
from agentauth.core.authority_binding import AuthorityBinding

class MyCorpProvider:
    name = "mycorp"

    def to_binding(self, raw, *, evidence_verified=True):
        return AuthorityBinding.from_verified_credential(
            raw,
            attestation_type="mycorp",
            evidence_verified=evidence_verified,
        )

    def build_session(self, raw, *, capability_authorizer=None, evidence_verified=True):
        binding = self.to_binding(raw, evidence_verified=evidence_verified)
        from agentauth.core.identity_protocol import IdentitySession
        return IdentitySession(binding=binding, capability_authorizer=capability_authorizer)

register_identity_provider(MyCorpProvider())
```

Register at process startup before calling `get_identity_provider("mycorp")`.

Never set `evidence_verified=True` unless you performed real cryptographic verification.

---

## AgentAuthCapabilityLayer

For frameworks that want a single “capability layer” object (used by receipts internally):

```python
from agentauth.capabilities.layer import AgentAuthCapabilityLayer

layer = AgentAuthCapabilityLayer()
# Implements CapabilityLayer protocol — issue/verify hooks for L3
```

Use this when building custom gateways rather than when writing a one-off script.

---

## Testing

```bash
pytest python/tests -q
```

Notable test modules:

- `test_identity_adapters.py` — all five providers × commit token path
- Other tests cover mandates, attenuation, and integration helpers

CI checks out **agentauth-identity** from GitHub alongside this repo and installs both before pytest.

---

## Running under iVisor (syscall-level enforcement)

`agentauth.capabilities.sandbox` compiles an envelope's **egress and path scope**
into iVisor sandbox policy, runs the work inside the guest, and returns iVisor's
unforgeable verdict stream as attested evidence. Everything else — recipients,
budgets, tool scope, argument binding — stays in the `SessionBroker`. The
sandbox is a peer of the broker, invoked *after* it allows:

```python
from agentauth.capabilities.sandbox import (
    SandboxRunSpec, run_sandboxed, attach_sandboxing)

decision = broker.authorize(action)
if decision.outcome is Outcome.ALLOW:
    outcome = run_sandboxed(SandboxRunSpec(
        elf=f"{rootfs}/usr/bin/python3", guest_args=("-u", "/work/task/run.py"),
        rootfs=rootfs, egress=egress, lease=lease, repo_root=repo,
        extra_files={"task/run.py": local_script}))
    attach_sandboxing(ctx, outcome.sandboxing)   # rides into the commit token
    assert not outcome.denied                    # verified verdicts only
```

Each run writes `<run_root>/<run_id>/` containing `ivisor.conf` (re-runnable by
hand), the staged `workspace/`, `trace.jsonl` (verified verdicts), and
`result.json`.

**Only trace-fd lines are evidence.** Policy-shaped lines a guest prints to
stdout/stderr land in `unverified_claims` and are never scored; if iVisor cannot
use the trace fd, `trace_degraded` makes attestation fail closed
(`evidence_ok: false`, outcome `indeterminate`).

Real runs need Apple Silicon and a signed sentry — **sign a copy**, since
signing a binary another process is executing can kill it:

```bash
cp <iVisor>/target/release/ivisor /tmp/ivisor-signed
codesign --force --sign - --entitlements <iVisor>/entitlements.plist \
    /tmp/ivisor-signed
IVISOR_E2E=1 IVISOR_BIN=/tmp/ivisor-signed \
IVISOR_ROOTFS=<iVisor>/guests/rootfs pytest python/tests/test_ivisor_e2e.py -q
```

Unit tests need none of that: `python/tests/fakes/fake_ivisor.py` honors the same
CLI, config, and trace-fd contract, so the driver is fully covered anywhere. Off
POSIX the driver raises `SandboxUnsupported`.

Swap the substrate by registering under the `agentauth.sandbox_backends` entry
point group (or `register_plugin("sandbox_backends", name, obj)`) and resolving
with `default_sandbox_backend(name)`.

See [ivisor_integration.md](ivisor_integration.md) for the lowering table and
the honest limits (subdomain narrowing, unenforced ports, `allow_all` refusal,
why `data_export_bytes` still fails closed).

---

## Project layout

| Path | Purpose |
|------|---------|
| `agentauth/capabilities/commit.py` | Commit token issue/verify |
| `agentauth/capabilities/identity_adapters/` | Five IdP adapters + registry |
| `agentauth/capabilities/integration.py` | Session → execution context |
| `agentauth/capabilities/layer.py` | `AgentAuthCapabilityLayer` |
| `agentauth/capabilities/sandbox/` | iVisor syscall-level enforcement + attestation |
| `agentauth/capabilities/compute_budget.py` | Compute-seconds ledger (sandbox-metered) |
| `demo/` | Runnable demo: sandbox policy recompiled every step from the trajectory |
| `agentauth/core/authority_binding.py` | Shared L1→L2/L3 contract |
| `agentauth/core/identity_protocol.py` | Protocol types |
| `examples/` | Runnable demos |
| `docs/cross_layer_integration.md` | Provider matrix and L3 snippets |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `No module named agentauth.identity` | L1 not installed | Install identity first |
| Adapter test fails one provider | Claim shape mismatch | Compare test fixtures in `test_identity_adapters.py` |
| Commit token verify fails | Wrong key, expired TTL, or mutated input | Re-issue; check clock skew |
| Mixed imports / stale code | Namespace merge from CWD | Use venv + pip install, not raw PYTHONPATH hacks |
| Git dependency install fails | Identity tag not pushed yet | Tag L1 before L2 release |

---

## Security practices

1. **Verify before trust** — adapters are not a substitute for IdP signature validation.
2. **Short TTLs** on commit tokens (minutes, not hours).
3. **Bind inputs** — include action input hash in the execution context when the action is parameterized.
4. **Attenuate sub-agents** — never widen scope when delegating; use Biscuit attenuation APIs.
5. **Pin versions** — mismatched L1/L2 tags are a common source of subtle verification bugs.

---

## Privacy and data handling

Layer 2 handles authorization context: subjects, tenants, action names, resource
references, leases, mandates, budgets, input commitments, and replay records.
Do not pass raw prompts, secrets, source code, or sensitive business payloads
through commit-token APIs when a canonical hash or stable reference is enough.

For production, configure replay-store retention, keep token TTLs short, redact
raw IdP tokens from logs, and document any external policy engine that receives
authorization context.

Read [docs/PRIVACY.md](PRIVACY.md) before routing production IdP claims or
business transactions through this layer.

---

## Releases

Tag **after** agentauth-core and agentauth-identity at the same semver line. Consumers install:

```bash
pip install "git+https://github.com/pberlizov/clay-seal-core.git@v0.5.0"
pip install "git+https://github.com/pberlizov/clay-seal-capabilities.git@v0.5.0"
```

See [CHANGELOG.md](../CHANGELOG.md) for release notes.

---

## Further reading

- [Layer 1 DEV_GUIDE](https://github.com/pberlizov/clayseal-identity/blob/main/docs/DEV_GUIDE.md)
- [Layer 3 DEV_GUIDE](https://github.com/pberlizov/clay-seal-receipts/blob/main/docs/DEV_GUIDE.md)
- [cross_layer_integration.md](cross_layer_integration.md)
- [Privacy and data handling](PRIVACY.md)
