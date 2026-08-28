"""A grant built from observed traffic is not an authorization of its own gaps.

Thirteen loaders build a task's grant from the tools its benign events happened
to use, and real deployments do the same thing when they derive a policy from a
recorded session. Every tool the observation missed is then refused, even when
the same mandate already authorizes that verb class. On tau2 that is 42.99% of
held-out benign events, and it is the deterministic form of the AgentDyn result
where open-ended tasks lose all utility.

`grant_is_observed=True` puts such a tool to the shape judge instead of refusing
it: the deployment's own catalogue, the sealed goal and the mandate's verb
classes, no argument values and no tool output. It is off by default and must
stay off wherever a human wrote the tool list, because there the list is an
authorization and widening it overrides the author.

The controls matter more than the headline here: a mechanism that admitted
everything would post the same false-block number.
"""

from __future__ import annotations

from clayseal.capabilities.broker import Outcome, SessionBroker
from clayseal.capabilities.monitor import Action
from clayseal.capabilities.replan import PlanExtender, catalog_shape_judge
from clayseal.capabilities.scoping.goal import GoalSpec
from clayseal.core.task_scope import TaskScope

CATALOG = frozenset({"read_email", "send_email", "toggle_roaming", "wipe_device"})


def _broker(*, advisory: bool, allowed_classes=("observe", "modify"), **kw):
    extender = PlanExtender(
        judge=catalog_shape_judge(allowed_classes=set(allowed_classes)),
        goal="keep the handset connected",
        catalog=sorted(CATALOG),
    )
    return SessionBroker(
        goal=GoalSpec(query_id="q", summary="keep the handset connected"),
        scope=TaskScope(allowed_resources=["mcp:tool:read_email"], allowed_actions=[]),
        allowed_tools={"read_email"},
        plan_extender=extender,
        tools_are_advisory=advisory,
        # The three enumerations move together or not at all: admitting the tool
        # alone just relocates the refusal to the resource gate, which is what
        # `grant_is_observed` exists to prevent a caller getting wrong.
        scope_is_advisory=advisory,
        tool_catalog=CATALOG,
        **kw)


def _act(tool: str, verb: str = "modify", step: int = 0) -> Action:
    return Action(step=step, tool=tool, resource=f"mcp:tool:{tool}",
                  verb=verb, args={}, meta={})


def test_the_enumerated_tool_still_works() -> None:
    """Control: the grant itself must keep working, advisory or not."""
    for advisory in (False, True):
        d = _broker(advisory=advisory).authorize(_act("read_email", "observe"))
        assert d.outcome is Outcome.ALLOW, (advisory, d.reasons)


def test_off_by_default_a_missing_tool_is_refused() -> None:
    d = _broker(advisory=False).authorize(_act("toggle_roaming"))
    assert d.outcome is Outcome.DENY
    assert any("not granted" in r for r in d.reasons), d.reasons


def test_a_tool_whose_verb_class_the_mandate_permits_is_admitted() -> None:
    d = _broker(advisory=True).authorize(_act("toggle_roaming"))
    assert d.outcome is Outcome.ALLOW, d.reasons


def test_a_tool_outside_the_deployment_catalogue_is_never_admitted() -> None:
    """Control: extension can only reach what the deployment actually offers.

    Without this the mechanism would be "allow anything the agent names", which
    is the failure it is supposed to avoid.
    """
    d = _broker(advisory=True).authorize(_act("exfiltrate_all"))
    assert d.outcome is Outcome.DENY, d.reasons


def test_a_verb_class_the_mandate_never_granted_is_refused() -> None:
    """Control: admission is not automatic for catalogue membership.

    `wipe_device` is in the catalogue, but a mandate that permits observe and
    modify has not authorized destruction, and the sealed goal does not name it.
    """
    broker = _broker(advisory=True, allowed_classes=("observe",))
    d = broker.authorize(_act("wipe_device", "delete"))
    assert d.outcome is not Outcome.ALLOW, d.reasons


def test_the_number_of_admitted_tools_is_capped() -> None:
    broker = _broker(advisory=True)
    broker.max_scope_extensions = 1
    assert broker.authorize(_act("toggle_roaming", step=0)).outcome is Outcome.ALLOW
    second = broker.authorize(_act("send_email", "modify", step=1))
    assert second.outcome is Outcome.DENY, second.reasons


def test_admission_does_not_leak_into_the_callers_grant() -> None:
    """The resource path had exactly this bug: a mutation that outlived the
    broker and granted authority to every other session sharing the object."""
    grant = {"read_email"}
    broker = _broker(advisory=True)
    broker.allowed_tools = grant
    broker.authorize(_act("toggle_roaming"))
    assert grant == {"read_email"}, grant
