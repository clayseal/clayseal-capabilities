"""The capability layer's public surface, resolved on first use.

Importing this used to cost **89 ms** against a 31 ms bare interpreter, because
it eagerly imported all 57 names below. That pulled `cryptography`'s SSH
serialization (25 ms, via `clayseal.core.signing`) and `asyncio` (17 ms, via
`guardrail`) into every process that touched the package, including
`clayseal policy lint`, which needs neither. Four of the 57 appear anywhere in
the README; the rest are the advanced surface.

So the names are mapped to their modules here and imported on first access, per
PEP 562. `from clayseal.capabilities import Guardrail` behaves exactly as it did
— it just no longer decides that a linting run needs an SSH key parser.

`__all__` stays the authoritative list, and `__dir__` reports it, so `dir()`,
tab-completion and `from … import *` are unchanged. `test_lazy_exports.py`
asserts every name in `__all__` actually resolves, which is the failure this
arrangement can have that the eager one could not: a typo in the map is not an
ImportError at import time any more, it is an AttributeError later.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

#: Public name -> the submodule that defines it. One entry per name in `__all__`;
#: the test suite asserts the two agree in both directions.
_EXPORTS: dict[str, str] = {
    # obligations: precedence rules read from the sealed goal
    "Obligation": "obligations",
    "ObligationLedger": "obligations",
    "derive_obligations": "obligations",
    # identity: subjects that are counted but are not independent
    "IdentityLedger": "identity",
    "derive_identity_rules": "identity",
    # freshness: the justification an invalidator poisoned
    "FreshnessLedger": "freshness",
    "Invalidation": "freshness",
    "derive_invalidations": "freshness",
    # entities: which counterparty the sealed goal named
    "EntityBinding": "entities",
    "EntityLedger": "entities",
    "bindings_from_intent": "entities",
    "derive_bindings": "entities",
    # authorizers
    "cedar_authorizer": "authorizers",
    "external_authorizer": "authorizers",
    "opa_authorizer": "authorizers",
    "openfga_authorizer": "authorizers",
    # call_budget
    "CallBudgetConfig": "call_budget",
    "CallReservation": "call_budget",
    "SessionCallBudget": "call_budget",
    "call_budget_config_from_mandate": "call_budget",
    "session_call_budget_from_mandate": "call_budget",
    # commit
    "CommitToken": "commit",
    "InMemoryUsedTokenStore": "commit",
    "SignedCommitToken": "commit",
    "UsedTokenStore": "commit",
    "issue_commit_token": "commit",
    "trusted_minting_keys_from_env": "commit",
    "verify_commit_token": "commit",
    # delegation
    "DelegationToken": "delegation",
    "issue_delegation": "delegation",
    "sign_delegation": "delegation",
    "verify_delegation_chain": "delegation",
    # deployable_stack
    "DeployableStack": "deployable_stack",
    "StackDecision": "deployable_stack",
    # guardrail
    "Guardrail": "guardrail",
    "GuardrailError": "guardrail",
    "Refused": "guardrail",
    "StepUpRequired": "guardrail",
    # layer
    "AgentAuthCapabilityLayer": "layer",
    "default_capability_layer": "layer",
    "get_capability_layer": "layer",
    "list_capability_layers": "layer",
    "register_capability_layer": "layer",
    # mandate
    "Mandate": "mandate",
    "issue_mandate": "mandate",
    "verify_mandate_signature": "mandate",
    # mandate_budgets
    "MandateBudgets": "mandate_budgets",
    "UnsupportedBudgetType": "mandate_budgets",
    "session_budgets_from_mandate": "mandate_budgets",
    # operations
    "capability_allows": "operations",
    "operation_for_action": "operations",
    "operation_for_mcp_tool": "operations",
    # scoping
    "CapabilityLease": "scoping",
    "GoalSpec": "scoping",
    "build_capability_lease": "scoping",
    "build_repo_chunk_index": "scoping",
    # session_memory
    "SessionMemory": "session_memory",
    # task_scope
    "TaskScope": "task_scope",
    "compile_task_scope": "task_scope",
    # used_token_store
    "DynamoDBUsedTokenStore": "used_token_store",
    "RedisUsedTokenStore": "used_token_store",
    "default_used_token_store": "used_token_store",
    "load_used_token_store_from_env": "used_token_store",
    "set_default_used_token_store": "used_token_store",
    # value_budget
    "SessionValueBudget": "value_budget",
    "ValueBudgetConfig": "value_budget",
    "ValueReservation": "value_budget",
    "session_value_budget_from_mandate": "value_budget",
    "value_budget_config_from_mandate": "value_budget",
}

if TYPE_CHECKING:
    # Type checkers do not run `__getattr__`, so the eager imports are kept for
    # them. This block is never executed at runtime.
    from clayseal.capabilities.authorizers import (
        cedar_authorizer,
        external_authorizer,
        opa_authorizer,
        openfga_authorizer,
    )
    from clayseal.capabilities.call_budget import (
        CallBudgetConfig,
        CallReservation,
        SessionCallBudget,
        call_budget_config_from_mandate,
        session_call_budget_from_mandate,
    )
    from clayseal.capabilities.commit import (
        CommitToken,
        InMemoryUsedTokenStore,
        SignedCommitToken,
        UsedTokenStore,
        issue_commit_token,
        trusted_minting_keys_from_env,
        verify_commit_token,
    )
    from clayseal.capabilities.delegation import (
        DelegationToken,
        issue_delegation,
        sign_delegation,
        verify_delegation_chain,
    )
    from clayseal.capabilities.deployable_stack import DeployableStack, StackDecision
    from clayseal.capabilities.guardrail import (
        Guardrail,
        GuardrailError,
        Refused,
        StepUpRequired,
    )
    from clayseal.capabilities.layer import (
        AgentAuthCapabilityLayer,
        default_capability_layer,
        get_capability_layer,
        list_capability_layers,
        register_capability_layer,
    )
    from clayseal.capabilities.mandate import (
        Mandate,
        issue_mandate,
        verify_mandate_signature,
    )
    from clayseal.capabilities.mandate_budgets import (
        MandateBudgets,
        UnsupportedBudgetType,
        session_budgets_from_mandate,
    )
    from clayseal.capabilities.operations import (
        capability_allows,
        operation_for_action,
        operation_for_mcp_tool,
    )
    from clayseal.capabilities.scoping import (
        CapabilityLease,
        GoalSpec,
        build_capability_lease,
        build_repo_chunk_index,
    )
    from clayseal.capabilities.session_memory import SessionMemory
    from clayseal.capabilities.task_scope import TaskScope, compile_task_scope
    from clayseal.capabilities.used_token_store import (
        DynamoDBUsedTokenStore,
        RedisUsedTokenStore,
        default_used_token_store,
        load_used_token_store_from_env,
        set_default_used_token_store,
    )
    from clayseal.capabilities.value_budget import (
        SessionValueBudget,
        ValueBudgetConfig,
        ValueReservation,
        session_value_budget_from_mandate,
        value_budget_config_from_mandate,
    )


def __getattr__(name: str):
    """Resolve a public name to its module on first access (PEP 562).

    The resolved object is cached in this module's namespace, so the lookup
    happens once per name per process and every later access is an ordinary
    global.
    """
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    value = getattr(importlib.import_module(f"{__name__}.{module}"), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(__all__)


__all__ = [
    "AgentAuthCapabilityLayer",
    "CallBudgetConfig",
    "CallReservation",
    "CapabilityLease",
    "CommitToken",
    "DelegationToken",
    "DeployableStack",
    "DynamoDBUsedTokenStore",
    "EntityBinding",
    "EntityLedger",
    "FreshnessLedger",
    "GoalSpec",
    "Guardrail",
    "GuardrailError",
    "IdentityLedger",
    "InMemoryUsedTokenStore",
    "Invalidation",
    "Mandate",
    "MandateBudgets",
    "Obligation",
    "ObligationLedger",
    "RedisUsedTokenStore",
    "Refused",
    "SessionCallBudget",
    "SessionMemory",
    "SessionValueBudget",
    "SignedCommitToken",
    "StackDecision",
    "StepUpRequired",
    "TaskScope",
    "UnsupportedBudgetType",
    "UsedTokenStore",
    "ValueBudgetConfig",
    "ValueReservation",
    "bindings_from_intent",
    "build_capability_lease",
    "build_repo_chunk_index",
    "call_budget_config_from_mandate",
    "capability_allows",
    "cedar_authorizer",
    "compile_task_scope",
    "default_capability_layer",
    "default_used_token_store",
    "derive_bindings",
    "derive_identity_rules",
    "derive_invalidations",
    "derive_obligations",
    "external_authorizer",
    "get_capability_layer",
    "issue_commit_token",
    "issue_delegation",
    "issue_mandate",
    "list_capability_layers",
    "load_used_token_store_from_env",
    "opa_authorizer",
    "openfga_authorizer",
    "operation_for_action",
    "operation_for_mcp_tool",
    "register_capability_layer",
    "session_budgets_from_mandate",
    "session_call_budget_from_mandate",
    "session_value_budget_from_mandate",
    "set_default_used_token_store",
    "sign_delegation",
    "trusted_minting_keys_from_env",
    "value_budget_config_from_mandate",
    "verify_commit_token",
    "verify_delegation_chain",
    "verify_mandate_signature",
]
