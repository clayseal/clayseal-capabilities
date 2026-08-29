# Developer guide

How to operate Clay Seal. Start with the gateway, which is what most deployments
use; the primitives underneath it are documented after, because you need them
only when you are building something the gateway does not already do.

If you have not seen it work yet, run `clayseal try` first. It takes a minute,
needs no key and no configuration, and every verdict it prints comes from the
gateway this guide describes.

If you are looking for the shortest path to a running system, it is
[the policy document](POLICY.md) and `clayseal proxy`. If you are looking for
what the layer defends and what it does not, that is
[THREAT_MODEL.md](THREAT_MODEL.md).

---

## What this enforces

One question, per action: **may this agent do this exact thing, right now,
against this resource, with these arguments, given everything it has already
done?**

The last clause is the one that distinguishes it. Per-call authorization answers
the first four and cannot answer the fifth, so an agent that issues eleven
refunds of $900 each against a $1,000 ceiling passes every individual check.
Measured across twelve business-process scenarios, per-call enforcement handed
the policy lands at 55.0% violation against 56.2% undefended
([bpl_shared_policy.md](../benchmarks/results/bpl_shared_policy.md)).

Three things follow from that, and they shape the whole API:

- Authorization is **per session**, not per call. The gateway is a stateful
  object that lives as long as the task.
- The gateway needs to be **told what the agent read**, not only what it is
  about to do, because that is what separates a destination the user asked for
  from one a document supplied.
- A refusal is **evidence**, so every decision goes on a hash-chained log
  whether it was allowed or not.

---

## Position in the stack

```
┌─────────────────────────────────────────┐
│  L3 agentauth-receipts                  │
│  Receipts, audit, MCP gateway, verify   │
└─────────────────┬───────────────────────┘
                  │ IdentitySession, CapabilityLayer
┌─────────────────▼───────────────────────┐
│  L2 clayseal              ← YOU ARE HERE │
│  Commit tokens, mandates, leases, budgets │
└─────────────────┬───────────────────────┘
                  │ AuthorityBinding, verified L1 claims
┌─────────────────▼───────────────────────┐
│  L1 agentauth-identity                  │
│  JWT-SVID, Biscuit, PoP, identity svc   │
└─────────────────────────────────────────┘
```

**Dependency rule:** there is no private dependency. `clayseal.core` ships in
this distribution. The optional Biscuit backend needs `agentauth-identity`, which
is a separate distribution and is not required to use this layer: bring your own
`CapabilityTokenBackend` through the `agentauth.capability_backends` entry point.

**Import convention:**

```python
from agentauth.identity import AgentAuth          # from layer 1
from clayseal.capabilities.commit import issue_commit_token
from clayseal.capabilities.identity_adapters import get_identity_provider
```

There is no top-level `from agentauth import …` in this repo alone.

---

## Installation

```bash
pip install clayseal
```

Two runtime dependencies, `cryptography` and `pyyaml`.

### From a checkout

```bash
git clone https://github.com/pberlizov/clayseal.git
cd clayseal
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### Verify

```bash
pytest python/tests -q
ruff check clayseal
python examples/01_gateway.py
clayseal policy lint examples/policy.yaml
```

---

## The gateway

### In front of the tools

The enforcement point most deployments want is a process, not an import. The
agent connects to `clayseal proxy` and `clayseal proxy` runs the real MCP server,
so a refused call is answered with a JSON-RPC error and the server subprocess
never receives the frame.

```bash
clayseal proxy --policy policy.yaml -- npx @your-org/mcp-server
```

In a client that reads an MCP config, put the proxy where the server used to be:

```json
{
  "mcpServers": {
    "billing": {
      "command": "clayseal",
      "args": ["proxy", "--policy", "/etc/clayseal/billing.yaml",
               "--", "npx", "@your-org/mcp-server"]
    }
  }
}
```

Two things happen. Every `tools/call` is authorized before it is forwarded, and
`tools/list` is filtered to the policy, so the agent is never offered a tool it
would then be refused. The proxy refuses to start on a policy error rather than
enforcing a document whose author did not mean what it says.

What this does and does not mediate is worth stating exactly. It covers every
call on that transport. An agent that can reach the same capability another way,
through its own network access or a server it started itself, is outside the
boundary, and closing that is what the syscall tier is for.

A `STEP_UP` reaches the agent as a refusal that names the reason. Nothing in a
stdio proxy can hold a call open while a person is asked, and forwarding it
because it was not a hard deny would turn the supervised profile into the
autonomous one at the transport layer.

### In the process

When you own the harness, call the gateway directly. This is the same object the
proxy runs.

```python
from clayseal.capabilities.monitor.action import Action
from clayseal.capabilities.policy import load_policy
from clayseal.capabilities.tool_verbs import classify_verb

gateway = load_policy("examples/policy.yaml").build()

agent_calls = [("read_ticket", {"id": "T-1042"}, ()),
               ("send_email", {"to": "ops@acme-internal.com"}, ("tickets/T-1042.txt",))]

for step, (tool, args, cited_context_ids) in enumerate(agent_calls):
    decision = gateway.authorize(Action(
        step=step,
        tool=tool,
        resource=f"mcp:tool:{tool}",
        verb=classify_verb(tool),
        args=args,
        # Which context items the agent cited for this call. This is what the
        # taint layer reads, so an empty tuple means "nothing influenced this".
        derived_from=cited_context_ids,
    ))
    if not decision.allowed:
        # Hand the reasons back to the agent. A refusal it can read is a refusal
        # it can retry correctly, which is where most recovered utility comes from.
        print("refused:", decision.reasons)
        continue
    gateway.observe_output(tool, {"ok": True})
```

`classify_verb` is a default for callers who have only tool names. If you have a
real catalog or a mandate that declares each tool's effect, pass the verb
explicitly: a name-based classifier reads `check_out_book` as a read.

### Telling it what the agent read

```python
gateway.observe_context(ContextItem(
    item_id="tickets/T-1042.txt",
    trust=TrustLevel.UNTRUSTED,
    introduced_at_step=step,
    summary=document_text,
))
```

This is not optional detail. Without it every destination looks equally
well-sourced, and the provenance tier cannot tell a recipient the user named from
one an injected document supplied. `examples/01_gateway.py` is the whole loop in
40 lines, including the injection it refuses.

### Resolving a step-up

A step-up is a request for authority the floor refused, so the approval must be
signed. In production an unsigned one raises rather than applying.

```python
from clayseal.capabilities.step_up import sign_step_up_approval

approval = sign_step_up_approval(operator_approval, key=control_plane_key)
ok, reason = gateway.resolve_step_up(approval)
```

### Reading the evidence

```python
records = gateway.decision_log.records()      # hash-chained, tamper-evident
print(gateway.metrics.prevented_violations)
```

Configure a durable sink through `decision_sinks`. The default is a `NullSink`
that **counts what it drops**, so "nothing configured" and "configured and
working" do not look alike.

### Surviving a restart

The gateway holds session state, so a process that restarts mid-task loses the
running totals. Snapshot it into your own store:

```python
from clayseal.capabilities.session_state import restore, snapshot

state = snapshot(gateway.broker)              # plain JSON, taken under the lock
restore(rebuilt_broker, state)                # onto a broker built from the SAME policy
```

`restore` rebuilds and re-verifies the decision-log hash chain and refuses a
snapshot that does not verify. Authority is not carried in the snapshot, only
what the session accumulated, so a restore cannot widen a grant. Read-modify-write
around it needs your store's own compare-and-set.

### Choosing a posture

`profiles.py` names three points on the one axis that matters: what happens to an
action the floor cleared and the plan did not predict.

```python
from clayseal.capabilities.profiles import AUTONOMOUS, SUPERVISED

print(SUPERVISED.describe())        # the switches, and why each one is set
```

Set it in the policy document rather than at the call site. Passing a posture
switch to `build()` is refused, because a call site quietly changing the posture
is exactly the failure the document exists to prevent.

---

## Core concepts

### AuthorityBinding

Defined in `clayseal.core.authority_binding` (shipped from this repo’s `clayseal.core` package, shared conceptually with L1/L3). It is the **normalized output of layer 1 verification**:

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

- **Mandates**, signed task descriptions that bound what an agent session may do.
- **Leases**, time- and scope-bounded capability containers for sandboxes.
- **Value budgets**, numeric limits (e.g. dollar amount, token count) enforced across a session.

Layer 3’s sandbox builder consumes these; layer 2 owns the primitives.

### CapabilityTokenBackend

Pluggable attenuation (default: Biscuit). Lets you swap macaroon-style backends if needed without changing commit-token APIs.

---

## Day-to-day operations

### Native Clay Seal path (L1 + L2)

The common case when you control both identity and capabilities:

```python
from agentauth.identity import AgentAuth
from clayseal.capabilities.integration import execution_context_from_session
from clayseal.capabilities.commit import (
    InMemoryUsedTokenStore,
    issue_commit_token,
    verify_commit_token,
)
from clayseal.core.signing import generate_keypair

auth = AgentAuth(trust_domain="example.org")
agent = auth.register_agent("bots/payment-agent")
credential = auth.identify(agent, principal="finance-bot@example.org", ttl_seconds=600)

session = auth.session(credential).wrap()  # or build via adapter below
# Prefer adapter for symmetry with cross-provider code:
from clayseal.capabilities.identity_adapters import get_identity_provider
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

`issue_commit_token` is the opposite contract: there is no "no" to return, so a
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
from clayseal.capabilities.identity_adapters import get_identity_provider
from clayseal.capabilities.integration import execution_context_from_session
from clayseal.capabilities.commit import (
    InMemoryUsedTokenStore,
    issue_commit_token,
    verify_commit_token,
)
from clayseal.core.signing import generate_keypair

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
from clayseal.capabilities.identity_adapters import get_identity_provider
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
from clayseal.capabilities.identity_adapters.registry import register_identity_provider
from clayseal.core.authority_binding import AuthorityBinding

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
        from clayseal.core.identity_protocol import IdentitySession
        return IdentitySession(binding=binding, capability_authorizer=capability_authorizer)

register_identity_provider(MyCorpProvider())
```

Register at process startup before calling `get_identity_provider("mycorp")`.

Never set `evidence_verified=True` unless you performed real cryptographic verification.

---

## AgentAuthCapabilityLayer

For frameworks that want a single “capability layer” object (used by receipts internally):

```python
from clayseal.capabilities.layer import AgentAuthCapabilityLayer

layer = AgentAuthCapabilityLayer()
# Implements CapabilityLayer protocol, issue/verify hooks for L3
```

Use this when building custom gateways rather than when writing a one-off script.

---

## Testing

```bash
pytest python/tests -q
```

Notable test modules:

- `test_identity_adapters.py`, all five providers × commit token path
- Other tests cover mandates, attenuation, and integration helpers

CI checks out **agentauth-identity** from GitHub alongside this repo and installs both before pytest.

---

## Running under iVisor (syscall-level enforcement)

`clayseal.capabilities.sandbox` compiles an envelope's **egress and path scope**
into iVisor sandbox policy, runs the work inside the guest, and returns iVisor's
unforgeable verdict stream as attested evidence. Everything else, recipients,
budgets, tool scope, argument binding, stays in the `SessionBroker`. The
sandbox is a peer of the broker, invoked *after* it allows:

```python
from clayseal.capabilities.sandbox import (
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

Real runs need Apple Silicon and a signed sentry, **sign a copy**, since
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
| `clayseal/capabilities/commit.py` | Commit token issue/verify |
| `clayseal/capabilities/identity_adapters/` | Five IdP adapters + registry |
| `clayseal/capabilities/integration.py` | Session → execution context |
| `clayseal/capabilities/layer.py` | `AgentAuthCapabilityLayer` |
| `clayseal/capabilities/sandbox/` | iVisor syscall-level enforcement + attestation |
| `clayseal/capabilities/compute_budget.py` | Compute-seconds ledger (sandbox-metered) |
| `demo/` | Runnable demo: sandbox policy recompiled every step from the trajectory |
| `clayseal/core/authority_binding.py` | Shared L1→L2/L3 contract |
| `clayseal/core/identity_protocol.py` | Protocol types |
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

1. **Verify before trust**, adapters are not a substitute for IdP signature validation.
2. **Short TTLs** on commit tokens (minutes, not hours).
3. **Bind inputs**, include action input hash in the execution context when the action is parameterized.
4. **Attenuate sub-agents**, never widen scope when delegating; use Biscuit attenuation APIs.
5. **Pin the minting key.** A signature proves integrity, not authority. Set
   `CLAYSEAL_COMMIT_TOKEN_TRUSTED_KEYS`, or pass `trusted_minting_keys`. The
   same applies to the intent envelope, which is the object `reclear` swaps
   mid-session.
6. **Share the replay store** across instances. An in-memory store on two
   gateways makes a single-use token usable twice.
7. **Leave the guards closed.** `CLAYSEAL_ENV=development` relaxes items 5 and
   6 and the step-up signature requirement. It warns once per process; do not
   let that warning become normal.

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

This distribution stands alone, so a release is one tag here.

```bash
pip install clayseal
```

Before tagging: `pytest python/tests -q`, `ruff check clayseal`, and build the
wheel and import every shipped module from it in an environment with no source
tree on the path. CI does the last one, because a lazy import inside a method is
fine in a checkout and a `ModuleNotFoundError` in every real install.

See [CHANGELOG.md](../CHANGELOG.md) for release notes.

---

## Further reading

- [The policy document](POLICY.md)
- [Threat model and key management](THREAT_MODEL.md)
- [Syscall-level enforcement](ivisor_integration.md)
- [cross_layer_integration.md](cross_layer_integration.md)
- [Privacy and data handling](PRIVACY.md)
- [Benchmark methodology and results](../benchmarks/README.md)
