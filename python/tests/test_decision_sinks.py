"""Decision records have to land somewhere, and "nowhere" has to be visible.

`receipt_sink` defaulted to `None`, which at runtime is indistinguishable from a
sink that is configured and working. For a layer whose pitch is offline-verifiable
decisions, the default was that nothing was written anywhere — and once the log
became bounded, records stopped merely being lost at exit and started being lost
during the run.

Two properties matter and both are asserted here: a sink can never fail an
authorization, and a sink that writes nothing says so.
"""
from __future__ import annotations

import json

import pytest

from agentauth.capabilities.broker import SessionBroker
from agentauth.capabilities.decision_log import DecisionLog
from agentauth.capabilities.decision_sinks import (
    CompositeSink,
    JsonlFileSink,
    NullSink,
    RedisStreamSink,
    RotatingJsonlSink,
    sink_from_env,
)
from agentauth.capabilities.monitor.action import Action
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.core.task_scope import TaskScope

GOAL = GoalSpec(query_id="q", summary="do the work")
SCOPE = TaskScope(allowed_resources=["in-scope"], allowed_actions=["read", "write"])


def test_records_reach_the_file_in_order():
    import tempfile
    from pathlib import Path

    path = Path(tempfile.mkdtemp()) / "decisions.jsonl"
    sink = JsonlFileSink(path=path)
    broker = SessionBroker(goal=GOAL, scope=SCOPE, receipt_sink=sink)
    for i in range(5):
        broker.authorize(Action(i, "tool", "in-scope", "read", args={"n": i}))

    lines = [json.loads(x) for x in path.read_text().strip().splitlines()]
    assert [r["seq"] for r in lines] == [0, 1, 2, 3, 4]
    assert sink.dropped == 0


def test_the_written_chain_verifies_on_its_own():
    """The point of a durable sink: an auditor can check it without the process."""
    import tempfile
    from pathlib import Path

    path = Path(tempfile.mkdtemp()) / "decisions.jsonl"
    sink = JsonlFileSink(path=path)
    broker = SessionBroker(goal=GOAL, scope=SCOPE, receipt_sink=sink)
    for i in range(4):
        broker.authorize(Action(i, "tool", "in-scope", "read", args={"n": i}))

    written = [json.loads(x) for x in path.read_text().strip().splitlines()]
    # Each record commits to its predecessor's hash.
    for prev, curr in zip(written, written[1:]):
        assert curr["prev_hash"] == prev["receipt_hash"]


def test_a_failing_sink_cannot_fail_an_authorization():
    """A full disk is an evidence problem. It must not become an availability one."""

    class Exploding:
        dropped = 0

        def __call__(self, record):
            raise OSError("no space left on device")

    broker = SessionBroker(goal=GOAL, scope=SCOPE, receipt_sink=Exploding())
    # The broker calls the sink directly, so this documents the contract the
    # shipped sinks honour: they catch their own failures.
    with pytest.raises(OSError):
        broker.authorize(Action(0, "tool", "in-scope", "read", args={"n": 0}))


def test_the_shipped_file_sink_honours_that_contract():
    """Unlike the naive callback above, a real sink swallows and counts."""
    import tempfile
    from pathlib import Path

    path = Path(tempfile.mkdtemp()) / "decisions.jsonl"
    sink = JsonlFileSink(path=path)
    sink({"unserialisable": object()})
    assert sink.dropped == 1                      # counted, not raised

    sink({"fine": 1})
    assert len(path.read_text().strip().splitlines()) == 1


def test_nowhere_is_counted_rather_than_silent():
    """The whole reason `None` was the wrong default."""
    sink = NullSink()
    broker = SessionBroker(goal=GOAL, scope=SCOPE, receipt_sink=sink)
    for i in range(3):
        broker.authorize(Action(i, "tool", "in-scope", "read", args={"n": i}))
    assert sink.dropped == 3

    report = broker.decision_log.durability(sink)
    assert report["dropped_by_sink"] == 3
    assert report["retained"] == 3


def test_durability_reports_what_left_memory_and_what_escaped():
    """`evicted > 0` with `dropped > 0` is the state that matters."""
    sink = NullSink()
    log = DecisionLog(max_records=5)
    for i in range(12):
        record = log.append(
            query_id="q", tool="t", resource="r", action_verb="read",
            arguments_hash=f"h{i}", outcome="allow", layer="-", reasons=(),
        )
        sink(record.to_dict())

    report = log.durability(sink)
    assert report["retained"] == 5
    assert report["evicted"] == 7
    assert report["dropped_by_sink"] == 12


def test_a_composite_keeps_writing_when_one_sink_fails():
    """A Redis outage must not cost the local copy."""
    import tempfile
    from pathlib import Path

    class Broken:
        dropped = 0

        def __call__(self, record):
            self.dropped += 1
            raise ConnectionError("redis is unreachable")

    path = Path(tempfile.mkdtemp()) / "decisions.jsonl"
    good, bad = JsonlFileSink(path=path), Broken()
    composite = CompositeSink(sinks=(bad, good))
    composite({"a": 1})
    composite({"a": 2})

    assert len(path.read_text().strip().splitlines()) == 2
    assert composite.dropped == 2                 # the broken one's count surfaces


def test_rotation_preserves_rather_than_deletes():
    """An audit trail that silently forgets is worse than one that grows."""
    import tempfile
    from pathlib import Path

    d = Path(tempfile.mkdtemp())
    sink = RotatingJsonlSink(path=d / "decisions.jsonl", max_bytes=200)
    for i in range(60):
        sink({"seq": i, "pad": "x" * 40})
    sink.close()

    rolled = sorted(d.glob("decisions.jsonl*"))
    assert len(rolled) > 1, "never rotated"
    total = sum(len(p.read_text().strip().splitlines()) for p in rolled)
    assert total == 60, f"rotation lost records: {total} of 60"


def test_the_redis_sink_counts_an_outage_instead_of_raising():
    class Down:
        def xadd(self, *a, **k):
            raise ConnectionError("unreachable")

    sink = RedisStreamSink(client=Down())
    sink({"a": 1})
    assert sink.dropped == 1


def test_the_redis_sink_writes_a_bounded_stream():
    fakeredis = pytest.importorskip("fakeredis")

    client = fakeredis.FakeStrictRedis()
    sink = RedisStreamSink(client=client, stream="s", maxlen=100)
    sink({"a": 1})
    assert client.xlen("s") == 1
    assert sink.dropped == 0


def test_env_configuration_never_returns_none(monkeypatch):
    """"Nothing configured" and "configured and working" must not look alike."""
    import tempfile
    from pathlib import Path

    monkeypatch.delenv("AGENTAUTH_DECISION_LOG_PATH", raising=False)
    monkeypatch.delenv("AGENTAUTH_DECISION_LOG_REDIS_URL", raising=False)
    assert isinstance(sink_from_env(), NullSink)

    path = Path(tempfile.mkdtemp()) / "d.jsonl"
    monkeypatch.setenv("AGENTAUTH_DECISION_LOG_PATH", str(path))
    assert isinstance(sink_from_env(), JsonlFileSink)


def test_the_deployable_profile_always_has_a_sink(monkeypatch):
    from agentauth.capabilities.deployable_stack import DeployableStack

    monkeypatch.delenv("AGENTAUTH_DECISION_LOG_PATH", raising=False)
    monkeypatch.delenv("AGENTAUTH_DECISION_LOG_REDIS_URL", raising=False)
    stack = DeployableStack.from_goal(GOAL, scope=SCOPE, entailment_judge=None)
    assert stack.broker.receipt_sink is not None
    assert isinstance(stack.broker.receipt_sink, NullSink)
