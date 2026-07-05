"""Default L2 capability layer for receipts integration."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentauth.capabilities.commit import issue_commit_token, verify_commit_token
from agentauth.capabilities.task_scope import compile_task_scope
from agentauth.core.identity_protocol import CapabilityLayer


@dataclass
class AgentAuthCapabilityLayer:
    name: str = "agentauth"

    def issue_commit_token(self, ctx: Any, *, key: Any, ttl_seconds: int) -> Any:
        return issue_commit_token(ctx, key=key, ttl_seconds=ttl_seconds)

    def verify_commit_token(self, signed: Any, *, ctx: Any) -> tuple[bool, str | None]:
        return verify_commit_token(signed, ctx=ctx)

    def compile_task_scope(self, mandate: dict[str, Any]) -> Any:
        return compile_task_scope(mandate)


default_capability_layer = AgentAuthCapabilityLayer()
