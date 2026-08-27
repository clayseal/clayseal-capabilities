"""`from_goal` runs the mandate coverage check, and it is advisory by default.

A linter nobody calls is a tool, not a control. `stress_aggregation.py`'s
remaining escapes are all mandate-completeness problems, so the check has to run
on the path every deployment goes through, but it cannot *block* that path by
default, because the benchmark harnesses in this repository build intentionally
incomplete mandates in order to measure the escape. Blocking them would delete
the measurement.

Hence: populate always, raise only on `strict_mandate=True`.
"""
import pytest

from agentauth.capabilities.deployable_stack import DeployableStack
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.capabilities.value_budget import (
    SessionValueBudget,
    ValueBudgetConfig,
)

GOAL = GoalSpec(query_id="q1", summary="move money")


def _budget():
    return SessionValueBudget(config=ValueBudgetConfig(
        tracked={"payments.transfer": ("amount", "p")}, ceilings={"p": 100}))


def _stack(tools, **kw):
    return DeployableStack.from_goal(
        GOAL, allowed_tools=set(tools), value_budget=_budget(),
        entailment_judge=None, **kw)


def test_from_goal_reports_an_uncovered_money_tool():
    stack = _stack({"payments.transfer", "payments.wire"})
    codes = {f.code for f in stack.mandate_findings}
    assert "untracked-effectful-tool" in codes


def test_the_check_is_advisory_by_default():
    # Must not raise: the escape has to stay measurable.
    stack = _stack({"payments.transfer", "payments.wire"})
    assert stack.broker is not None


def test_strict_mandate_refuses_to_construct():
    with pytest.raises(ValueError, match="payments.wire"):
        _stack({"payments.transfer", "payments.wire"}, strict_mandate=True)


def test_strict_mandate_tolerates_a_warning_only_mandate():
    """A session-scoped ceiling is a warning, and warnings must not block.

    Every budget object in this library is session-scoped, so treating that as an
    error would make `strict_mandate` unusable, which is how a strict mode ends
    up switched off everywhere.
    """
    stack = _stack({"payments.transfer"}, strict_mandate=True)
    codes = {f.code for f in stack.mandate_findings}
    assert codes == {"session-scoped-ceiling"}


def test_the_check_never_breaks_construction_on_an_odd_budget():
    class _Odd:
        config = object()          # no `tracked`, no `ceilings`

    stack = DeployableStack.from_goal(
        GOAL, allowed_tools={"payments.transfer"}, value_budget=_Odd(),
        entailment_judge=None)
    assert stack.broker is not None
