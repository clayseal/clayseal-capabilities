"""A sealed capability: the declarative envelope one agent task runs inside.

Built from real Clay Seal Capabilities (layer 2) primitives:

  - TypedGoalEnvelope  : coarse structural envelope (verb / tool / resource class)
  - task_scope         : goal-bound writable-path scoping
  - SessionCallBudget  : a ceiling on a tracked action (here: outbound connects)
  - an ordered plan    : the phase in which egress is legitimate

iVisor enforces the syscall floor; a Capability decides whether each observed
action was inside this envelope, and the behavioral-policy-limit (BPL) layers
decide whether the *sequence* stayed inside it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from clayseal.capabilities.call_budget import CallBudgetConfig, SessionCallBudget
from clayseal.capabilities.monitor import TypedGoalEnvelope
from clayseal.capabilities.scoping.goal import GoalSpec
from clayseal.core.task_scope import TaskScope, task_scope_allows_path


@dataclass
class Capability:
    goal: GoalSpec
    writable_paths: list[str]
    egress_hosts: frozenset[str]
    # behavioral-policy-limit knobs (0 / None disables that BPL layer)
    egress_budget: int | None = None      # max outbound connects the task may make
    egress_phase_only: bool = False       # egress illegitimate once the task finalizes

    # derived
    envelope: TypedGoalEnvelope = field(init=False)
    _scope: TaskScope = field(init=False)

    def __post_init__(self) -> None:
        self.envelope = TypedGoalEnvelope.from_goal(self.goal)
        self._scope = TaskScope(
            allowed_paths=self.writable_paths,
            task_summary=self.goal.summary,
            mandate_id=self.goal.query_id,
        )

    # --- instance-level checks ---------------------------------------------
    def write_in_scope(self, path: str) -> bool:
        return task_scope_allows_path(self._scope, path)

    def egress_authorized(self, host: str | None) -> bool:
        return host is not None and host in self.egress_hosts

    # --- behavioral-policy-limit: a fresh egress call budget per run --------
    def new_egress_budget(self) -> SessionCallBudget | None:
        if not self.egress_budget:
            return None
        cfg = CallBudgetConfig(
            tracked={"net.connect": "egress"},
            ceilings={"egress": self.egress_budget},
        )
        return SessionCallBudget(config=cfg)


# ---------------------------------------------------------------------------
# Builders, a couple of reusable sealed capabilities scenarios draw from.
# ---------------------------------------------------------------------------
def pkg_install_capability(
    *,
    query_id: str,
    egress_hosts: tuple[str, ...] = ("pypi.org", "files.pythonhosted.org"),
    egress_budget: int | None = None,
    egress_phase_only: bool = False,
) -> Capability:
    """The default coding-agent task: install a package into /work from PyPI."""
    goal = GoalSpec(
        query_id=query_id,
        summary="Install a Python package into the task workspace from PyPI",
        allow_resources=[f"net:{h}" for h in egress_hosts]
        + ["file:/work", "proc:/usr/bin/python3"],
        structured_intent={
            "kind": "pkg-install",
            # no "bind": a package install never opens a listening socket
            "verbs": ["read", "create", "write", "exec", "connect", "resolve"],
            "tools": ["process", "fs", "net"],
            "allow_writes": True,
        },
    )
    return Capability(
        goal=goal,
        writable_paths=["/work", "/work/*"],  # fnmatch '*' crosses '/'
        egress_hosts=frozenset(egress_hosts),
        egress_budget=egress_budget,
        egress_phase_only=egress_phase_only,
    )
