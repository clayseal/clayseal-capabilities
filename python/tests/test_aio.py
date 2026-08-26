"""The async façade: the event loop stays free and the decisions stay ordered.

Driven with `asyncio.run` inside ordinary sync tests rather than with
`pytest-asyncio`. The library has two runtime dependencies and the point of this
module is to be reachable from an async runtime, not to add a third to test it.
"""
from __future__ import annotations

import asyncio

import pytest

from agentauth.capabilities.aio import AsyncStack, wrap
from agentauth.capabilities.monitor.action import Action
from agentauth.capabilities.policy import load_policy_text

POLICY = """
version: 1
goal: {id: g, summary: Pay approved invoices}
profile: supervised
tools:
  allow: [pay_vendor, read_file]
  effects: {pay_vendor: transfer, read_file: read}
paths:
  allow: ["/finance/ap/**"]
  arg_names: {read_file: path}
  pathless: [pay_vendor]
budgets:
  value:
    ceilings: {payments: "1000"}
    tracked: {pay_vendor: {arg: amount, budget: payments}}
"""


def _stack() -> AsyncStack:
    return wrap(load_policy_text(POLICY).build())


def _pay(step: int, amount: str) -> Action:
    return Action(step=step, tool="pay_vendor", resource="mcp:tool:pay_vendor",
                  verb="transfer", args={"amount": amount}, meta={})


def _read(step: int) -> Action:
    path = "/finance/ap/a.json"
    return Action(step=step, tool="read_file", resource=path, verb="read",
                  args={"path": path}, meta={"path": path})


def test_a_decision_can_be_awaited():
    async def run():
        return await _stack().authorize(_pay(1, "100"))

    assert asyncio.run(run()).outcome == "allow"


def test_the_event_loop_keeps_running_during_decisions():
    """The reason this exists. An advisory tier that reaches the network would
    otherwise stall every other coroutine in the process."""

    async def run():
        stack = _stack()
        ticks = 0

        async def heartbeat():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.001)
                ticks += 1

        beat = asyncio.create_task(heartbeat())
        for i in range(100):
            await stack.authorize(_read(i))
        beat.cancel()
        return ticks

    assert asyncio.run(run()) > 0


def test_a_batch_is_decided_in_order_and_the_budget_holds():
    """Not `gather`: budgets, trajectory and envelope all accumulate, so
    deciding a batch concurrently against one session would race the state the
    aggregate rung is counted over."""

    async def run():
        stack = _stack()
        return await stack.authorize_all([_pay(i, "400") for i in range(1, 4)])

    assert [d.outcome for d in asyncio.run(run())] == ["allow", "allow", "deny"]


def test_the_awaitables_are_not_shadowed_by_the_wrapped_object():
    """`__getattr__` runs only for names this class does not define, so
    `authorize` stays async even though the wrapped stack has a sync one."""
    stack = _stack()
    assert asyncio.iscoroutinefunction(stack.authorize)
    assert asyncio.iscoroutinefunction(stack.authorize_all)
    assert asyncio.iscoroutinefunction(stack.resolve_step_up)


def test_everything_else_passes_through_unchanged():
    stack = _stack()
    assert stack.broker is stack.stack.broker
    with pytest.raises(AttributeError):
        _ = stack.no_such_attribute


def test_two_coroutines_on_one_stack_do_not_race_the_budget():
    """The broker holds an RLock, so concurrent entry serializes on the lock it
    would have serialized on anyway. The ceiling is 1000 and each pays 400."""

    async def run():
        stack = _stack()
        results = await asyncio.gather(
            *(stack.authorize(_pay(i, "400")) for i in range(1, 5)))
        return sorted(d.outcome for d in results)

    outcomes = asyncio.run(run())
    assert outcomes.count("allow") == 2, outcomes
