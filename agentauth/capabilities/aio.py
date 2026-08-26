"""An async surface, for the runtimes that have no other kind.

WHY THIS EXISTS

There are two ways to put this library in front of an agent, and until now each
had a blocker. Out of process, `clayseal proxy` speaks MCP over stdio, which is
local and single-client. In process, you import `DeployableStack` and call
`authorize`, which is synchronous, and there is **no `async def` anywhere in the
library**. Every agent runtime worth integrating with is async-first, so an
async agent talking to remote tools had neither path.

WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT

It is a façade. The decision core stays synchronous and pure, and that is a
property worth keeping rather than a limitation to route around: a decision that
is a pure function of an action and some state is one that replays, that a
benchmark can drive without a loop, and that a reviewer can read top to bottom.
Nothing here makes the floor async.

What it does is keep the event loop free. `authorize` is 60 to 140 microseconds
of pure CPU on a session of a few thousand actions
(`benchmarks/results/session_scaling.md`), which would be tolerable to call
inline. The advisory tiers are the problem: the entailment judge reaches a model
over the network, step-up resolution can reach a person, and a Redis-backed
ledger reaches a socket. Any of those on the loop stalls every other coroutine
in the process, and `broker.py` already documents an unbounded judge call as an
availability failure an attacker can trigger deliberately.

So every call is dispatched to a worker thread. The broker holds an `RLock` and
is safe under concurrent entry, which `test_broker_concurrency.py` pins, so two
coroutines authorizing against one stack serialize on the same lock they would
have serialized on anyway.

WHAT IT DOES NOT SOLVE

Threads are not free and this does not make the gateway concurrent: one stack is
one session and its decisions are ordered. What it removes is the stall, not the
ordering. A deployment wanting parallel authorization wants one stack per
session, which is what a stack already is.
"""
from __future__ import annotations

import asyncio
from typing import Any


class AsyncStack:
    """`DeployableStack`, awaited.

    Wraps rather than subclasses, so a stack built by any path (a policy, a
    profile, `from_goal`) can be handed here without knowing about this module.
    Anything not listed below is reachable on `.stack` and is synchronous, which
    is the honest default: a method that does no I/O has nothing to await.
    """

    def __init__(self, stack: Any) -> None:
        self.stack = stack

    async def authorize(self, action: Any) -> Any:
        """Decide one action without occupying the event loop."""
        return await asyncio.to_thread(self.stack.authorize, action)

    async def authorize_all(self, actions: Any) -> list[Any]:
        """Decide a batch IN ORDER, because a session is ordered.

        Deliberately not `asyncio.gather`. The budgets, the trajectory and the
        envelope all accumulate, so evaluating a batch concurrently against one
        session would race the very state the aggregate rung is counted over.
        The gather-shaped version of this is one stack per session, run
        concurrently, which is what a stack already is.
        """
        return await asyncio.to_thread(
            lambda: [self.stack.authorize(a) for a in actions])

    async def observe_output(self, *args: Any, **kwargs: Any) -> None:
        await asyncio.to_thread(
            lambda: self.stack.observe_output(*args, **kwargs))

    async def observe_context(self, *args: Any, **kwargs: Any) -> None:
        await asyncio.to_thread(
            lambda: self.stack.observe_context(*args, **kwargs))

    async def resolve_step_up(self, *args: Any, **kwargs: Any) -> Any:
        """The one call that genuinely waits on a person."""
        return await asyncio.to_thread(
            lambda: self.stack.resolve_step_up(*args, **kwargs))

    def __getattr__(self, name: str) -> Any:
        # Everything else, unchanged and synchronous. `__getattr__` runs only
        # for names this class does not define, so the awaitables above are
        # never shadowed by the wrapped object's synchronous versions.
        return getattr(self.stack, name)


def wrap(stack: Any) -> AsyncStack:
    """`AsyncStack(stack)`, named for the call site that reads better."""
    return AsyncStack(stack)
