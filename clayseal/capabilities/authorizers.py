"""Adapters for substituting external L2 authorization engines."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

DecisionInput = dict[str, Any]
DecisionOutput = Mapping[str, Any] | bool
DecisionEvaluator = Callable[[DecisionInput], DecisionOutput]
AuthorizerInputFactory = Callable[[str, str], DecisionInput]


def _decision_to_authorizer_result(provider: str, decision: DecisionOutput) -> dict[str, Any]:
    if isinstance(decision, bool):
        return {"allowed": decision, "provider": provider}
    result = dict(decision)
    if "allowed" not in result:
        if "allow" in result:
            result["allowed"] = bool(result["allow"])
        elif "decision" in result:
            result["allowed"] = bool(result["decision"])
    result.setdefault("allowed", False)
    result.setdefault("provider", provider)
    return result


def external_authorizer(
    provider: str,
    evaluator: DecisionEvaluator,
    *,
    input_factory: AuthorizerInputFactory | None = None,
) -> Callable[[str, str], dict[str, Any]]:
    """Return a ``CapabilityAuthorizer`` backed by an external decision engine."""

    def authorize(resource: str, action: str) -> dict[str, Any]:
        decision_input = (
            input_factory(resource, action)
            if input_factory is not None
            else {"resource": resource, "action": action}
        )
        return _decision_to_authorizer_result(provider, evaluator(decision_input))

    return authorize


def opa_authorizer(
    evaluator: DecisionEvaluator,
    *,
    principal: str | None = None,
    context: Mapping[str, Any] | None = None,
) -> Callable[[str, str], dict[str, Any]]:
    """Create an OPA/Rego-style capability authorizer.

    ``evaluator`` can be a local Rego test double or a thin client that posts
    the returned input shape to an OPA sidecar.
    """

    def build_input(resource: str, action: str) -> DecisionInput:
        payload: DecisionInput = {
            "input": {
                "resource": resource,
                "action": action,
                "context": dict(context or {}),
            }
        }
        if principal is not None:
            payload["input"]["principal"] = principal
        return payload

    return external_authorizer("opa", evaluator, input_factory=build_input)


def cedar_authorizer(
    evaluator: DecisionEvaluator,
    *,
    principal: str,
    context: Mapping[str, Any] | None = None,
) -> Callable[[str, str], dict[str, Any]]:
    """Create an Amazon Cedar-style capability authorizer."""

    def build_input(resource: str, action: str) -> DecisionInput:
        return {
            "principal": principal,
            "action": action,
            "resource": resource,
            "context": dict(context or {}),
        }

    return external_authorizer("cedar", evaluator, input_factory=build_input)


def openfga_authorizer(
    evaluator: DecisionEvaluator,
    *,
    user: str,
    relation_for_action: Callable[[str], str] | None = None,
    object_for_resource: Callable[[str], str] | None = None,
) -> Callable[[str, str], dict[str, Any]]:
    """Create an OpenFGA-style tuple-check capability authorizer."""

    def build_input(resource: str, action: str) -> DecisionInput:
        relation = relation_for_action(action) if relation_for_action else action
        object_id = object_for_resource(resource) if object_for_resource else resource
        return {"user": user, "relation": relation, "object": object_id}

    return external_authorizer("openfga", evaluator, input_factory=build_input)
