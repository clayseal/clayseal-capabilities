"""Commit-token flow using any of the five built-in identity providers."""
from clayseal.capabilities.commit import (
    InMemoryUsedTokenStore,
    issue_commit_token,
    verify_commit_token,
)
from clayseal.capabilities.identity_adapters import get_identity_provider, list_identity_providers
from clayseal.capabilities.integration import execution_context_from_session
from clayseal.core.signing import generate_keypair

DEMO = {
    "spiffe_jwt": {
        "sub": "spiffe://example.org/customer/ten_demo/agent/bot/demo",
        "iss": "spiffe://example.org",
        "scope": "payroll:write",
    }
}

provider_name = "spiffe_jwt"
raw = DEMO[provider_name]
session = get_identity_provider(provider_name).build_session(raw)
key = generate_keypair()
ctx = execution_context_from_session(
    session,
    action_name="mcp.tools/call/issue_payroll_bonus",
    resource_ref="demo:issue_payroll_bonus",
    input={"employee_id": "emp_001", "bonus_amount": 100},
    query_id="demo",
)
signed = issue_commit_token(ctx, key=key, ttl_seconds=300)
# Both arguments are required unless CLAYSEAL_ENV names a development
# environment. Pinning the minter is what makes a signature mean authority
# rather than only integrity; the store is what makes the token single-use.
ok, reason = verify_commit_token(
    signed,
    ctx=ctx,
    trusted_minting_keys={key.public_key_hex},
    used_token_store=InMemoryUsedTokenStore(),   # share it across instances
)
print("providers:", list_identity_providers())
print("provider:", provider_name, "verified:", ok, reason)
assert ok
