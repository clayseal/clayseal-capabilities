"""Cross-provider identity adapter coverage + L2 commit-token e2e."""
from __future__ import annotations

import pytest

from agentauth.capabilities.commit import issue_commit_token, verify_commit_token
from agentauth.capabilities.identity_adapters import get_identity_provider, list_identity_providers
from agentauth.capabilities.integration import execution_context_from_session
from agentauth.core.signing import generate_keypair

PROVIDER_FIXTURES = {
    "agentauth": {
        "agent_id": "agt_demo",
        "spiffe_id": "spiffe://acme.ai/customer/ten_demo/agent/researcher/abc",
        "agent_type": "researcher",
        "owner": "alice@acme.ai",
        "scopes": ["db:read"],
        "capabilities": [{"resource": "db", "action": "read"}],
        "expires_at": "2099-01-01T00:00:00Z",
    },
    "spiffe_jwt": {
        "sub": "spiffe://example.org/customer/ten_demo/agent/bot/xyz",
        "iss": "spiffe://example.org",
        "scope": "db:read api:write",
        "exp": "2099-01-01T00:00:00Z",
    },
    "oidc": {
        "sub": "agent-007",
        "iss": "https://login.example.com",
        "scope": "transactions:read transactions:write",
        "org_id": "org_demo",
        "exp": "2099-01-01T00:00:00Z",
    },
    "auth0": {
        "sub": "client|m2m-demo",
        "iss": "https://demo.auth0.com/",
        "scope": "read:agents write:agents",
        "permissions": ["approve:bonus"],
        "org_id": "org_demo",
        "gty": "client-credentials",
        "exp": "2099-01-01T00:00:00Z",
    },
    "aws_sts": {
        "Arn": "arn:aws:sts::123456789012:assumed-role/agent-role/session",
        "Account": "123456789012",
        "UserId": "AROAEXAMPLE:session",
        "scopes": ["s3:read"],
    },
    "azure_ad": {
        "oid": "obj-123",
        "tid": "tenant-123",
        "iss": "https://sts.windows.net/tenant-123/",
        "scp": "api.read",
        "roles": ["Agent.Executor"],
        "appid": "app-123",
    },
    "gcp_service_account": {
        "email": "agent@project.iam.gserviceaccount.com",
        "project_id": "project-1",
        "scope": "cloud-platform",
    },
}


def test_five_identity_providers_registered():
    names = list_identity_providers()
    for expected in (
        "agentauth",
        "spiffe_jwt",
        "oidc",
        "auth0",
        "aws_sts",
        "azure_ad",
        "gcp_service_account",
    ):
        assert expected in names


def test_each_provider_produces_verified_binding():
    for name, raw in PROVIDER_FIXTURES.items():
        binding = get_identity_provider(name).to_binding(raw)
        assert binding.evidence_verified
        assert binding.subject_id
        assert binding.authority_id
        assert binding.issuer


@pytest.mark.parametrize("provider", list(PROVIDER_FIXTURES))
def test_commit_token_across_identity_providers(provider):
    session = get_identity_provider(provider).build_session(PROVIDER_FIXTURES[provider])
    key = generate_keypair()
    ctx = execution_context_from_session(
        session,
        action_name="mcp.tools/call/issue_payroll_bonus",
        resource_ref="rippling-hr:issue_payroll_bonus",
        input={"employee_id": "emp_001", "bonus_amount": 100},
        query_id=f"q-{provider}",
    )
    signed = issue_commit_token(ctx, key=key, ttl_seconds=120)
    ok, reason = verify_commit_token(signed, ctx=ctx)
    assert ok, reason
