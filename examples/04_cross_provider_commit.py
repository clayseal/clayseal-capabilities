"""Commit-token flow using any of the five built-in identity providers."""
from agentauth.capabilities.identity_adapters import get_identity_provider, list_identity_providers
from agentauth.capabilities.integration import execution_context_from_session
from agentauth.capabilities.commit import issue_commit_token, verify_commit_token
from agentauth.core.signing import generate_keypair

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
ok, reason = verify_commit_token(signed, ctx=ctx)
print("providers:", list_identity_providers())
print("provider:", provider_name, "verified:", ok, reason)
assert ok
