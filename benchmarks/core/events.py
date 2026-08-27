"""Dataset-agnostic event and task model for the enforcement benchmark.

Every external benchmark (AgentDojo, InjecAgent, ToolEmu, ...) is normalized to
the same shape: a task carries the authorization a legitimate user granted
(``mandate`` / ``capabilities``), plus a stream of attempted tool calls, each
labeled ``BENIGN`` (the user's own task steps, should be allowed) or ``ATTACK``
(steps induced by a prompt injection / compromised tool, should be blocked).

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

    # The corpus does not say. Replayed so stateful rungs (budget, velocity)

    # see the real event stream, but scored on neither axis.

    #

    # Added for SLEIGHT, where the loader labelled every tool call in an

    # attack transcript ATTACK, including the agent's legitimate cover work.

    # A covert-sabotage transcript is mostly the real task: of 323 tool calls

    # across 44 attack transcripts the corpus's own `mechanism` annotation

    # cites 129. The other 194 are the work the attack hides behind, and

    # counting them as attack inflated the denominator with events that are

    # not the attack. Calling them BENIGN is the opposite error, because the

    # corpus certifies its benign.jsonl twin and not an attack transcript's

    # quiet lines, so they are scored on neither side.

    UNLABELED = "unlabeled"

    BENIGN = "benign"  # a legitimate step of the user's own task, expect ALLOW
    ATTACK = "attack"  # an injected / out-of-scope step, expect DENY


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
    ``clayseal.core.task_scope.compile_task_scope`` (an ``allowed_resources`` /
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
    # A grant restated as PATTERNS rather than an enumeration of instances, which
    # is how an operator writes a mandate ("the reservation tools", `/app/**`)
    # and not how a logger records one. None means the grant is an exact instance
    # list and every engine behaves exactly as it did before patterns existed;
    # that identity is what makes the level-0 column of the generalisation sweep
    # a reproduction of the shipped numbers rather than a re-measurement.
    # Built by `benchmarks.core.patterns`.
    tool_patterns: list[str] | None = None
    resource_patterns: list[str] | None = None
    # Per-CALL argument binding: for each tool, the list of argument shapes that
    # were legitimately authorized (one commit token per real call). A tool
    # present here is bound, a call whose args match none of its authorized
    # shapes is rejected, so a tool called many times with different valid args
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
