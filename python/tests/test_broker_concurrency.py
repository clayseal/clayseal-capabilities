"""What a concurrent session did to the broker, measured rather than assumed.

An agent gateway serves one session from several threads: a model that emits
parallel tool calls, an async runtime, a worker pool behind a request. Nothing in
`SessionBroker` was synchronised — no lock in `broker.py`, `session_memory.py`,
`session_grants.py` or `decision_log.py` — while `value_budget`, `call_budget`,
`velocity`, `staleness` and `principal_ledger` all take one.

The findings below are separated by how strong the evidence for each is, because
"this is a race" and "this race reproduces" are different claims.

DEMONSTRATED
    The hash-chained decision log forks. `DecisionLog.append` reads `head_hash`,
    canonicalises a record against it and appends; that window spans a JSON
    serialisation, which is wide enough to interleave. Measured on the
    unsynchronised broker with 32 threads and a 1ns switch interval: **20 trials
    out of 20 produced a chain that fails its own `verify()`**. An audit trail
    that reports tampering because of its own writer is worse than none, since
    the failure is indistinguishable from the thing it exists to detect.

NOT REPRODUCED, GUARDED ANYWAY
    `audits_spent` (the human-attention ceiling) and `_consumed` (the single-use
    approval ledger) are both check-then-act on a counter, which is a race by
    construction. Neither could be provoked: at 64 threads, a budget of 1 and a
    1ns switch interval, 30 trials never asked twice. The read-modify-write is a
    handful of bytecodes and CPython's GIL does not switch inside it in practice.

    They are asserted here regardless. The guarantee they rest on is an
    implementation detail of one interpreter — it does not hold on a
    free-threaded build, and it stops holding here the moment anything is added
    between the compare and the increment. These tests state the invariant so
    that change fails loudly instead of silently widening the window.
"""

from __future__ import annotations

import threading

from agentauth.capabilities.broker import Outcome, SessionBroker
from agentauth.capabilities.monitor.action import Action
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.core.task_scope import TaskScope

GOAL = GoalSpec(query_id="race", summary="do the work")
#: A scope that admits the tool but not the resource, so every action takes the
#: soft-scope-miss path and asks for a step-up. That is the cheapest way to make
#: the audit budget the thing under test.
SCOPE = TaskScope(
    allowed_resources=["in-scope"],
    allowed_actions=["read", "write", "send"],
)

THREADS = 32


def _run_concurrently(fn, n: int = THREADS) -> list:
    results: list = [None] * n
    barrier = threading.Barrier(n)

    def worker(i: int) -> None:
        barrier.wait()  # release them together, so they actually contend
        results[i] = fn(i)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def test_the_audit_budget_is_not_overspent():
    """Invariant guard. Not reproduced under the GIL — see the module docstring."""
    budget = 3
    broker = SessionBroker(
        goal=GOAL, scope=SCOPE, audit_budget=budget, on_audit_exhausted="deny"
    )

    decisions = _run_concurrently(
        lambda i: broker.authorize(
            Action(i, "tool", f"out-of-scope-{i}", "write", args={"n": i})
        )
    )

    asked = [d for d in decisions if d.outcome is Outcome.STEP_UP]
    assert len(asked) == budget, (
        f"asked a human {len(asked)} times against a budget of {budget}"
    )
    assert broker.audits_spent == budget
    # Everything past the budget denies rather than silently proceeding.
    denied = [d for d in decisions if d.outcome is Outcome.DENY]
    assert len(denied) == THREADS - budget
    assert all(
        any("audit budget exhausted" in r for r in d.reasons) for d in denied
    )


def test_one_approval_clears_exactly_one_action():
    """Invariant guard, same status as the budget above.

    The request is built and registered directly, the way
    `test_step_up_resolution.py` does, because the rule has to carry a
    CLASSIFIED violation code — an unclassified one is refused before the
    single-use check is ever reached, which would leave the ledger untested.
    """
    from agentauth.capabilities.step_up import (
        StepUpApproval,
        bind_to_action,
        build_step_up_request,
        sign_step_up_approval,
    )
    from agentauth.core.signing import generate_keypair

    broker = SessionBroker(goal=GOAL, scope=SCOPE)
    request = bind_to_action(
        build_step_up_request(
            request_id="r1", query_id="race",
            resource_ref="mcp:tool:send_money", operation="send",
            violations=["egress to 'novel.test' not on allow-list"],
        ),
        tool="send_money", arguments_hash="sha256:aaa", layer="floor",
    )
    assert "unclassified" not in request.codes, request.codes
    broker._pending[request.commitment()] = request

    approval = sign_step_up_approval(
        StepUpApproval(
            approval_id="a-1",
            request_commitment=request.commitment(),
            allow_resources=["mcp:tool:send_money"],
            allow_write=True,
        ),
        key=generate_keypair(),
    )

    outcomes = _run_concurrently(lambda _i: broker.resolve_step_up(approval))
    accepted = [ok for ok, _reason in outcomes if ok]
    assert len(accepted) == 1, f"one approval resolved {len(accepted)} times"

    rejected = [reason for ok, reason in outcomes if not ok]
    assert all(
        "already used" in r or "answers no request" in r for r in rejected
    ), rejected


def test_the_decision_chain_stays_verifiable_under_concurrency():
    """The demonstrated one: 20 of 20 trials broke the chain without the lock."""
    broker = SessionBroker(goal=GOAL, scope=SCOPE)
    _run_concurrently(
        lambda i: broker.authorize(Action(i, "tool", "in-scope", "read", args={"n": i}))
    )

    ok, reason = broker.decision_log.verify()
    assert ok, reason
    records = broker.decision_log.records()
    assert len(records) == THREADS
    # Sequence numbers dense and unique — no record overwrote another.
    assert sorted(r["seq"] for r in records) == list(range(THREADS))


def test_the_trajectory_matches_what_actually_executed():
    """Append-then-maybe-rollback is the widest window in `authorize`.

    An action goes onto the trajectory before the behavioural layer runs and is
    popped if that layer refuses. The pop is guarded by `actions[-1] is action`,
    so an interleaved append leaves a refused action on the trajectory, and every
    later `feasible`, `last_deviation` and detector call then judges the session
    against a step that never ran.
    """
    broker = SessionBroker(goal=GOAL, scope=SCOPE)
    decisions = _run_concurrently(
        lambda i: broker.authorize(
            Action(
                i, "tool",
                "in-scope" if i % 2 == 0 else f"out-of-scope-{i}",
                "write", args={"n": i},
            )
        )
    )

    executed = [d for d in decisions if d.outcome is Outcome.ALLOW]
    assert len(broker._trajectory.actions) == len(executed)


def test_every_mutating_entry_point_takes_the_lock():
    """The facade is the guarantee; this is what stops a new path bypassing it."""
    import inspect

    for name in (
        "authorize", "resolve_step_up", "commit_plan",
        "reclear", "observe_context", "observe_output", "note_edit",
    ):
        source = inspect.getsource(getattr(SessionBroker, name))
        assert "with self._lock:" in source, f"{name} does not take the session lock"
        assert f"_{name}_locked" in source, f"{name} does not delegate to its impl"
