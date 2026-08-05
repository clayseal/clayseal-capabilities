"""Lifting verified verdicts into the behavioral layer's action stream."""
from agentauth.capabilities.monitor.action import Trajectory, action_token
from agentauth.capabilities.sandbox.monitor_feed import (
    actions_from_events,
    extend_trajectory,
)
from agentauth.capabilities.sandbox.verdicts import parse_policy_line
from agentauth.capabilities.scoping.goal import GoalSpec


def _ev(line, *, verified=True):
    event = parse_policy_line(line, verified=verified)
    assert event is not None, line
    return event


def test_write_open_lifts_to_a_write_action():
    # 0o1101 = O_WRONLY|O_CREAT|O_TRUNC
    action = actions_from_events([_ev(
        "ivisor: policy fs.open verdict=allow root=workspace "
        "path=/work/out/report.txt flags=0o1101")])[0]
    assert (action.verb, action.tool) == ("write", "ivisor.fs")
    assert action.resource == "file:/work/out/report.txt"
    assert action.outcome == "allow"


def test_read_open_lifts_to_a_read_action():
    action = actions_from_events([_ev(
        "ivisor: policy fs.open verdict=allow root=workspace "
        "path=/work/data/a.txt flags=0o0")])[0]
    assert action.verb == "read"


def test_network_and_dns_events_map_to_net_resources():
    events = [
        _ev("ivisor: policy dns.query verdict=deny name=evil.example "
            "reason=not-allowlisted"),
        _ev("ivisor: policy net.connect verdict=deny dst=203.0.113.10:443 "
            "reason=not-allowlisted"),
    ]
    dns, connect = actions_from_events(events)
    assert (dns.verb, dns.resource) == ("read", "net:evil.example")
    assert (connect.verb, connect.resource) == ("send", "net:203.0.113.10:443")
    assert connect.outcome == "deny"


def test_exec_argv_is_decoded_into_a_list():
    action = actions_from_events([_ev(
        'ivisor: policy proc.exec verdict=allow path=/bin/sh '
        'argv=["sh","-c","echo hi"]')])[0]
    assert action.verb == "exec"
    assert action.args["argv"] == ["sh", "-c", "echo hi"]


def test_unverified_claims_are_dropped_by_default():
    # A guest-authored line must never reach the detector.
    forged = _ev("ivisor: policy net.connect verdict=allow dst=evil:443",
                 verified=False)
    assert actions_from_events([forged]) == []
    assert len(actions_from_events([forged], verified_only=False)) == 1


def test_misses_are_excluded_by_default():
    miss = _ev("ivisor: policy fs.open verdict=miss root=rootfs "
               "path=/Users/y/.ssh/id_ed25519 flags=0o0 errno=ENOENT")
    assert actions_from_events([miss]) == []
    assert len(actions_from_events([miss], include_miss=True)) == 1


def test_unmapped_events_are_skipped_not_fatal():
    assert actions_from_events([_ev(
        "ivisor: policy future.subsystem verdict=allow thing=x")]) == []


def test_steps_are_sequential_from_start_step():
    events = [_ev("ivisor: policy fs.mkdir verdict=allow path=/work/a"),
              _ev("ivisor: policy fs.unlink verdict=allow path=/work/b")]
    actions = actions_from_events(events, start_step=5)
    assert [a.step for a in actions] == [5, 6]
    assert [a.verb for a in actions] == ["create", "delete"]


def test_lifted_actions_tokenize_for_the_detector():
    action = actions_from_events([_ev(
        "ivisor: policy net.connect verdict=deny dst=203.0.113.10:443")])[0]
    token = action_token(action)
    assert token.startswith("send|ivisor.net|")


def test_extend_trajectory_appends_after_existing_actions():
    traj = Trajectory(goal=GoalSpec(query_id="q", summary="s"))
    extend_trajectory(traj, [_ev(
        "ivisor: policy fs.open verdict=allow path=/work/a flags=0o0")])
    extend_trajectory(traj, [_ev(
        "ivisor: policy net.connect verdict=deny dst=1.2.3.4:443")])
    assert [a.step for a in traj.actions] == [0, 1]


def test_meta_records_provenance():
    action = actions_from_events([_ev(
        "ivisor: policy fs.open verdict=deny path=/work/a flags=0o1101")])[0]
    assert action.meta["sandbox"] == "ivisor"
    assert action.meta["verified"] is True
    assert action.meta["verdict"] == "deny"
