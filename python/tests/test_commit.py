from agentauth.core.runtime import ActionDescriptor, AuthorityContext, ExecutionContext
from agentauth.core.signing import generate_keypair
from agentauth.capabilities.commit import issue_commit_token, verify_commit_token


def test_commit_token_roundtrip():
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
    ok, reason = verify_commit_token(signed, ctx=ctx)
    assert ok, reason
