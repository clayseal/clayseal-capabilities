"""Build the deployable gateway from a ``BenchmarkTask``.

This used to be ``DeployableStack.from_benchmark_task``, a classmethod on the
library class whose body did ``from benchmarks.core.detector_eval import
_goal_for``. The wheel ships ``only-include = ["agentauth/capabilities"]``, so
in any real install that import raises ``ModuleNotFoundError``, the library
depended on the harness that measures it. The import was lazy, so nothing caught
it until a caller reached the method, and the CI layering check only forbids
``agentauth.receipts``, ``agentauth.backend`` and top-level
``agentauth.identity``.

The direction of the dependency is now the only one that makes sense: the
benchmark knows about the library, the library knows nothing about the
benchmark. ``DeployableStack.from_goal`` is unchanged and is still the one
profile every path builds through, so this is a relocation and not a second
product, the mapping from a ``BenchmarkTask`` to that call is what lives here.
"""
from __future__ import annotations

from typing import Any

from agentauth.capabilities.call_budget import session_call_budget_from_mandate
from agentauth.capabilities.deployable_stack import DeployableStack
from agentauth.capabilities.monitor.action import Trajectory
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.capabilities.value_budget import session_value_budget_from_mandate
from agentauth.core.hash_util import hash_canonical_json
from agentauth.core.task_scope import compile_task_scope


def stack_from_benchmark_task(
    task: Any,
    *,
    goal: GoalSpec | None = None,
    declared_plan: Trajectory | None = None,
    entailment_judge: Any | None = ...,
    detector=None,
    scope_is_advisory: bool = False,
    require_declaration_for_egress: bool = False,
    intent_envelope: Any = ...,
    derive_counts: bool = False,
    inferrer: Any = None,
) -> DeployableStack:
    """Build the stack from a ``BenchmarkTask`` mandate (scoreboard / CTR).

    `intent_envelope` defaults to one compiled from the task's goal. It used to
    be absent entirely, so every structural analysis routed through here measured
    a stack with no envelope and therefore no goal-derived plan at all. Pass
    `None` to reproduce that, which is what the `derive_counts=False` arm below
    is for: the two together are how the count rung's contribution is attributed
    rather than assumed.
    """
    from benchmarks.core.detector_eval import _goal_for

    g = goal or _goal_for(task)
    mandate = task.mandate or {}
    # Path-scoped human authorizations compile with empty allowed_resources;
    # do NOT backfill path globs into allowed_resources, the broker treats
    # that field as exact resource ids (e.g. "workspace"), while paths are
    # checked via task_scope_allows_path. Ladder leaves resources empty.
    scope = compile_task_scope(mandate) if mandate else None

    auth_hashes = None
    if getattr(task, "authorized_args", None):
        auth_hashes = {
            tool: {hash_canonical_json(args) for args in shapes}
            for tool, shapes in task.authorized_args.items()
        }

    vb = (
        session_value_budget_from_mandate(
            mandate, tracked=getattr(task, "value_tracked", None) or set())
        if mandate else None
    )
    cb = (
        session_call_budget_from_mandate(
            mandate, tracked=getattr(task, "call_tracked", None) or set())
        if mandate else None
    )

    envelope = intent_envelope
    if envelope is ...:
        from agentauth.capabilities.monitor.generation import compile_envelope

        envelope = compile_envelope(
            g, derive_counts=derive_counts, inferrer=inferrer).envelope

    return DeployableStack.from_goal(
        g,
        intent_envelope=envelope,
        scope=scope,
        allowed_tools=set(task.allowed_tools) if task.allowed_tools else None,
        tool_patterns=list(task.tool_patterns) if task.tool_patterns else None,
        capabilities=list(task.capabilities) if task.capabilities else None,
        authorized_arg_hashes=auth_hashes,
        declared_plan=declared_plan,
        value_budget=vb,
        call_budget=cb,
        entailment_judge=entailment_judge,
        detector=detector,
        scope_is_advisory=scope_is_advisory,
        replay_pin_clock=True,
        require_declaration_for_egress=require_declaration_for_egress,
    )
