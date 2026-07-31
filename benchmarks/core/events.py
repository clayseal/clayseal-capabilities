"""Dataset-agnostic event and task model for the enforcement benchmark.

Every external benchmark (AgentDojo, InjecAgent, ToolEmu, ...) is normalized to
the same shape: a task carries the authorization a legitimate user granted
(``mandate`` / ``capabilities``), plus a stream of attempted tool calls, each
labeled ``BENIGN`` (the user's own task steps — should be allowed) or ``ATTACK``
(steps induced by a prompt injection / compromised tool — should be blocked).

An enforcement engine then decides allow/deny per event, and we score it on the
two axes that actually matter for an authorization layer:

- containment: fraction of ATTACK events blocked;
- friction:    fraction of BENIGN events wrongly blocked (false-block rate).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventLabel(str, Enum):
    """Ground-truth label for an attempted tool call."""

    BENIGN = "benign"  # a legitimate step of the user's own task — expect ALLOW
    ATTACK = "attack"  # an injected / out-of-scope step — expect DENY


@dataclass(frozen=True)
class BenchmarkEvent:
    """One attempted tool call to run through an enforcement decision.

    Fields are deliberately redundant so every rung of the enforcement ladder
    has what it needs without re-deriving it:

    - ``tool_name``  drives naive tool allowlists and MCP-tool mandates.
    - ``resource``/``action`` drive capability-token (``resource:action``) checks.
    - ``path``       drives path-scoped task-scope checks (file reads/writes).
    - ``args``       drive input-binding (commit-token argument-hash) checks.
    """

    event_id: str
    tool_name: str
    resource: str
    action: str
    label: EventLabel
    path: str | None = None
    args: dict[str, Any] = field(default_factory=dict)
    # Free-form provenance from the source dataset (suite, injection id, etc.).
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class BenchmarkTask:
    """A single scenario: the granted authorization plus the events to judge.

    ``mandate`` is a plain dict compilable by
    ``agentauth.core.task_scope.compile_task_scope`` (an ``allowed_resources`` /
    ``grant_id`` mandate or an ``allowed_paths`` human-authorization document).
    ``capabilities`` is the ``[{"resource","action"}, ...]`` list used by the
    capability-token engine. ``authorized_args`` records, per tool, the argument
    shape the user actually authorized, so input-binding can detect mutation.
    """

    task_id: str
    summary: str
    events: list[BenchmarkEvent]
    mandate: dict[str, Any] = field(default_factory=dict)
    capabilities: list[dict[str, str]] = field(default_factory=list)
    allowed_tools: set[str] = field(default_factory=set)
    # Per-CALL argument binding: for each tool, the list of argument shapes that
    # were legitimately authorized (one commit token per real call). A tool
    # present here is bound — a call whose args match none of its authorized
    # shapes is rejected — so a tool called many times with different valid args
    # is fully supported, while a mutated payload matches nothing. Absent tools
    # are unbound.
    authorized_args: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # Budget wiring for the aggregate-volume rung. ``value_tracked`` maps a tool
    # to the ``(arg_name, budget_id)`` its quantity debits (money moved, headcount
    # touched); ``call_tracked`` maps a tool to the ``budget_id`` each call debits.
    # The USD/count ceilings themselves live in ``mandate["budgets"]``. Empty here
    # ⇒ the budget rung is a pass-through for this task.
    value_tracked: dict[str, tuple[str, str]] = field(default_factory=dict)
    call_tracked: dict[str, str] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)

    def counts(self) -> tuple[int, int]:
        """Return ``(n_benign, n_attack)``."""
        benign = sum(1 for e in self.events if e.label is EventLabel.BENIGN)
        return benign, len(self.events) - benign


@dataclass(frozen=True)
class Decision:
    """An engine's ruling on one event."""

    allowed: bool
    reason: str
    engine: str
