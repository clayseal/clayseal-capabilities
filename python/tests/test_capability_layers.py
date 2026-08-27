from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from clayseal.capabilities.layer import (
    get_capability_layer,
    list_capability_layers,
    register_capability_layer,
)
from clayseal.capabilities.authorizers import (
    cedar_authorizer,
    external_authorizer,
    opa_authorizer,
    openfga_authorizer,
)


@dataclass
class DummyCapabilityLayer:
    name: str = "dummy"

    def issue_commit_token(self, ctx: Any, *, key: Any, ttl_seconds: int) -> dict[str, Any]:
        return {"ctx": ctx, "ttl_seconds": ttl_seconds}

    def verify_commit_token(self, signed: Any, *, ctx: Any) -> tuple[bool, str | None]:
        return (signed.get("ctx") == ctx, None)

    def compile_task_scope(self, mandate: dict[str, Any]) -> dict[str, Any]:
        return {"compiled": mandate}


def test_default_capability_layer_registered():
    assert "agentauth" in list_capability_layers()
    assert get_capability_layer("agentauth").name == "agentauth"


def test_custom_capability_layer_substitution():
    layer = DummyCapabilityLayer()
    register_capability_layer(layer)

    resolved = get_capability_layer("dummy")

    token = resolved.issue_commit_token({"action": "x"}, key="unused", ttl_seconds=30)
    ok, reason = resolved.verify_commit_token(token, ctx={"action": "x"})

    assert ok, reason
    assert resolved.compile_task_scope({"task": "demo"}) == {"compiled": {"task": "demo"}}


def test_external_authorizer_normalizes_decisions():
    authorizer = external_authorizer(
        "custom",
        lambda decision_input: {"allow": decision_input["action"] == "read", "reason": "policy"},
    )

    assert authorizer("repo://src", "read") == {
        "allow": True,
        "allowed": True,
        "provider": "custom",
        "reason": "policy",
    }
    assert authorizer("repo://src", "write")["allowed"] is False


def test_opa_cedar_and_openfga_authorizers_shape_inputs():
    seen: list[dict[str, Any]] = []

    def evaluator(decision_input: dict[str, Any]) -> bool:
        seen.append(decision_input)
        return True

    opa = opa_authorizer(evaluator, principal="agent-1", context={"tenant": "demo"})
    cedar = cedar_authorizer(evaluator, principal="User::agent-1")
    openfga = openfga_authorizer(
        evaluator,
        user="agent:agent-1",
        relation_for_action=lambda action: "viewer" if action == "read" else action,
        object_for_resource=lambda resource: f"document:{resource}",
    )

    assert opa("repo://src", "read")["provider"] == "opa"
    assert cedar("File::src", "read")["provider"] == "cedar"
    assert openfga("src", "read")["provider"] == "openfga"
    assert seen[0]["input"]["principal"] == "agent-1"
    assert seen[0]["input"]["context"] == {"tenant": "demo"}
    assert seen[1] == {
        "principal": "User::agent-1",
        "action": "read",
        "resource": "File::src",
        "context": {},
    }
    assert seen[2] == {"user": "agent:agent-1", "relation": "viewer", "object": "document:src"}
