"""Simulated approvers, exercised through the real signed resolution path."""
from __future__ import annotations

import pytest

from clayseal.capabilities.broker import SessionBroker
from clayseal.capabilities.scoping.goal import GoalSpec
from clayseal.capabilities.step_up import bind_to_action, build_step_up_request
from benchmarks.live.approver import (
    AlwaysApprove, BudgetedApprover, FatiguedApprover, GullibleApprover,
    NeverApprove, OracleApprover, build_approver,
)


def _broker():
    return SessionBroker(goal=GoalSpec(query_id="q", summary="s", allow_resources=[]))


def _request(i=0, tool="send_money", violations=None):
    return bind_to_action(
        build_step_up_request(
            request_id=f"r{i}", query_id="q", resource_ref=f"mcp:tool:{tool}",
            operation="send",
            violations=violations or ["egress to 'novel.test' not on allow-list"]),
        tool=tool, arguments_hash=f"sha256:{i}", layer="floor")


def _run(approver, n=4, **kw):
    broker, resolved = _broker(), 0
    for i in range(n):
        request = _request(i, **kw)
        broker._pending[request.commitment()] = request
        signed = approver.review(request)
        if signed is not None and broker.resolve_step_up(signed)[0]:
            resolved += 1
    return broker, resolved


def test_never_approve_resolves_nothing():
    """The regression control: with this approver every published autonomous
    number must reproduce exactly, which is what proves the resume machinery
    perturbed nothing."""
    broker, resolved = _run(NeverApprove())
    assert resolved == 0
    assert len(broker.grants) == 0


def test_always_approve_resolves_everything():
    broker, resolved = _run(AlwaysApprove())
    assert resolved == 4
    assert broker.grants.acquired()["human"] == 4


def test_the_approval_goes_through_real_signature_verification():
    """The harness must not weaken the path it measures. If this ever passes
    with an unsigned approval, the measured path and the deployed path differ."""
    broker, resolved = _run(AlwaysApprove(), n=1)
    assert resolved == 1


def test_oracle_approves_only_ground_truth_tools():
    broker, resolved = _run(OracleApprover(legitimate=frozenset({"read_file"})))
    assert resolved == 0
    _, allowed = _run(OracleApprover(legitimate=frozenset({"send_money"})))
    assert allowed == 4


def test_budgeted_stops_answering():
    _, resolved = _run(BudgetedApprover(limit=2), n=5)
    assert resolved == 2


def test_gullible_declines_an_alarming_card():
    """The adversary's best case: violation prose is partly attacker-authored,
    so an attacker who shapes how a request reads shapes whether it is approved."""
    _, routine = _run(GullibleApprover(), n=1)
    assert routine == 1
    _, alarming = _run(GullibleApprover(), n=1,
                       violations=["protected zone write"])
    assert alarming == 0


def test_the_fatigue_curve_is_monotone_and_bounded():
    """`at what interruption rate does ASR stop being zero` needs the curve to
    be monotone, or the answer is not a threshold."""
    approver = FatiguedApprover(base_p=0.0, fatigue_after=10, ceiling_p=1.0)
    probs = []
    for i in range(1, 16):
        approver.asked = i
        probs.append(approver.probability())
    assert probs == sorted(probs)
    assert probs[0] == 0.0 and probs[-1] == 1.0


def test_fatigue_is_seeded_and_reproducible():
    a = FatiguedApprover(base_p=0.5, fatigue_after=5, ceiling_p=0.5, seed=7)
    b = FatiguedApprover(base_p=0.5, fatigue_after=5, ceiling_p=0.5, seed=7)
    reqs = [_request(i) for i in range(20)]
    assert [a.decide(r) for r in reqs] == [b.decide(r) for r in reqs]


@pytest.mark.parametrize("spec,cls", [
    ("never", NeverApprove), ("always", AlwaysApprove),
    ("oracle", OracleApprover), ("gullible", GullibleApprover),
    ("budget3", BudgetedApprover), ("fatigued:0.2:8:0.9", FatiguedApprover),
    ("", NeverApprove), ("nonsense", NeverApprove),
])
def test_the_spec_parser_defaults_to_never(spec, cls):
    """An unrecognised token must not silently become a permissive approver."""
    assert isinstance(build_approver(spec), cls)


def test_stats_report_the_ask_and_approve_counts():
    approver = AlwaysApprove()
    _run(approver, n=3)
    stats = approver.stats()
    assert stats["asked"] == 3 and stats["approved"] == 3 and stats["rate"] == 1.0
