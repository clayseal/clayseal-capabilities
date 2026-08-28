"""Velocity, wired into the live floor.

A budget counts what an action is worth and a scope counts where it points.
Neither sees an action that costs nothing and names no target, which is the
shape of volume-defined harm. `velocity.SessionVelocity` contained 100% of it
at burst >= 10 with 0.00% clean false alarms (`benchmarks/results/burst.md`)
and had no runtime input: nothing constructed it on the product path.

The test that matters most is the pass-through: unconfigured must mean
unchanged, or every published number moves.
"""

from __future__ import annotations

from clayseal.capabilities.broker import Outcome, SessionBroker
from clayseal.capabilities.monitor import Action
from clayseal.capabilities.scoping.goal import GoalSpec
from clayseal.capabilities.velocity import (
    EFFECT_CLASS,
    SessionVelocity,
    VelocityConfig,
)
from clayseal.core.task_scope import TaskScope


def _broker(**kw):
    return SessionBroker(
        goal=GoalSpec(query_id="q", summary="send the summaries"),
        scope=TaskScope(allowed_resources=["mcp:tool:send_email"], allowed_actions=[]),
        **kw)


def _act(step: int = 0) -> Action:
    return Action(step=step, tool="send_email", resource="mcp:tool:send_email",
                  verb="send", args={}, meta={})


def _limiter(cap: int) -> SessionVelocity:
    return SessionVelocity(config=VelocityConfig(limits={EFFECT_CLASS: (cap, 3600.0)}))


def test_an_unpaced_session_is_unchanged() -> None:
    """The property that lets this ship: no velocity configured, no change."""
    broker = _broker()
    assert all(broker.authorize(_act(i)).outcome is Outcome.ALLOW for i in range(20))


def test_the_cap_stops_the_burst() -> None:
    broker = _broker(velocity=_limiter(3))
    outcomes = [broker.authorize(_act(i)).outcome for i in range(6)]
    assert outcomes[:3] == [Outcome.ALLOW] * 3
    assert Outcome.DENY in outcomes[3:], outcomes


def test_work_under_the_cap_is_not_touched() -> None:
    """Control: a cap that is never reached must refuse nothing.

    Without this, a limiter that denied everything would pass the test above.
    """
    broker = _broker(velocity=_limiter(50))
    outcomes = [broker.authorize(_act(i)).outcome for i in range(20)]
    assert outcomes == [Outcome.ALLOW] * 20


def test_the_denial_says_it_was_the_pace() -> None:
    broker = _broker(velocity=_limiter(1))
    broker.authorize(_act(0))
    decision = broker.authorize(_act(1))
    assert decision.outcome is Outcome.DENY
    assert any("velocity" in r.lower() or "rate" in r.lower() or "limit" in r.lower()
               for r in decision.reasons), decision.reasons


def test_a_refused_action_does_not_keep_the_budget_it_reserved() -> None:
    """Velocity runs after the budgets reserve, so a refusal must release them.

    If it does not, one paced-out action silently spends budget the caller
    never used, and the ceiling drifts down for the rest of the session.
    """
    from clayseal.capabilities.call_budget import CallBudgetConfig, SessionCallBudget

    calls = SessionCallBudget(config=CallBudgetConfig(
        tracked={"send_email": "sends"}, ceilings={"sends": 10}))
    broker = _broker(velocity=_limiter(2), call_budget=calls)
    for i in range(5):
        broker.authorize(_act(i))
    remaining = calls.remaining("sends")
    assert remaining == 8, (
        f"2 actions were allowed but {10 - remaining} calls were charged; "
        f"a paced refusal is leaking its reservation"
    )
