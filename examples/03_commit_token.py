"""Standalone commit-token mint and verify (layer 2)."""
from clayseal.core.runtime import ActionDescriptor, AuthorityContext, ExecutionContext
from clayseal.core.signing import generate_keypair
from clayseal.capabilities.commit import (
    InMemoryUsedTokenStore,
    issue_commit_token,
    verify_commit_token,
)

key = generate_keypair()
args = {"employee_id": "emp_001", "bonus_amount": 100}
ctx = ExecutionContext(
    action=ActionDescriptor(
        action_name="mcp.tools/call/issue_payroll_bonus",
        resource_ref="rippling-hr:issue_payroll_bonus",
    ),
    input=args,
    authority=AuthorityContext(authority_id="rippling-action-agent", tenant_id="ten_demo"),
    query_id="q-demo",
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
print("verified:", ok, reason)
assert ok
