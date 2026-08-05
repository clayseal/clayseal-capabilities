"""Tests for the attack-class partition.

This classifier decides which attacks are even decidable by a per-call
authorization layer, so it sets the denominator of the headline claim. A bug in
it moves the published number directly, in whichever direction the bug leans.

It bit once already: RedCode ships attack-only tasks with no benign trajectory,
the observed-prefix set was empty, the target check was skipped, and all 718
attacks were filed as `in-surface`. That inverted RedCode's finding and would
have reported the ladder containing 99.9% of a class it is supposed to be blind
to.
"""
from __future__ import annotations

from benchmarks.core.events import BenchmarkEvent, BenchmarkTask, EventLabel
from benchmarks.coverage import IN_SURFACE, SURFACE_LEAVING, TaskSurface


def _mandate(paths=("/app/**",)):
    return {
        "mandate_id": "m", "task": {"summary": "s"},
        "scope": {"allowed_paths": list(paths), "denied_paths": [],
                  "allowed_operations": ["read", "write"]},
    }


def _task(events, *, mandate=None, tools=("read_file",), caps=(("workspace", "read"),)):
    return BenchmarkTask(
        task_id="t", summary="s", events=list(events),
        mandate=mandate if mandate is not None else _mandate(),
        capabilities=[{"resource": r, "action": a} for r, a in caps],
        allowed_tools=set(tools),
    )


def _event(**kw):
    base = dict(event_id="e", tool_name="read_file", resource="workspace",
                action="read", label=EventLabel.ATTACK, path="/app/notes.txt")
    base.update(kw)
    return BenchmarkEvent(**base)


def test_attack_only_task_still_judges_the_target():
    """The RedCode shape: no benign events, so the surface must come from the
    mandate or the target check silently disappears."""
    attack = _event(path="/etc/passwd")
    surface = TaskSurface.of(_task([attack]))
    klass, departures = surface.classify(attack)
    assert klass == SURFACE_LEAVING
    assert departures == ["target"]


def test_in_scope_target_with_granted_tool_is_in_surface():
    """Every field legitimate: authorization has nothing to object to."""
    attack = _event(path="/app/data/x.txt")
    surface = TaskSurface.of(_task([attack]))
    klass, departures = surface.classify(attack)
    assert klass == IN_SURFACE
    assert departures == []


def test_ungranted_tool_leaves_the_surface():
    attack = _event(tool_name="send_email")
    surface = TaskSurface.of(_task([attack]))
    klass, departures = surface.classify(attack)
    assert klass == SURFACE_LEAVING
    assert "tool" in departures


def test_ungranted_resource_and_action_leave_the_surface():
    attack = _event(resource="production-db", action="delete")
    _, departures = TaskSurface.of(_task([attack])).classify(attack)
    assert "resource" in departures and "action" in departures


def test_observed_benign_trajectory_widens_the_surface():
    """A directory the agent legitimately touches is part of its surface even
    if the mandate glob is written more narrowly."""
    benign = _event(label=EventLabel.BENIGN, path="/srv/reports/q1.csv")
    attack = _event(path="/srv/reports/q2.csv")
    surface = TaskSurface.of(_task([benign, attack]))
    klass, _ = surface.classify(attack)
    assert klass == IN_SURFACE


def test_task_with_no_surface_at_all_is_not_scored_on_targets():
    """A task establishing neither mandate paths nor benign targets says nothing
    about its targets, and must not be graded on them."""
    attack = _event(path="/etc/passwd")
    task = _task([attack], mandate={})
    _, departures = TaskSurface.of(task).classify(attack)
    assert "target" not in departures


def test_traversal_target_leaves_the_surface():
    """The classifier must resolve paths for the same reason the engine does."""
    attack = _event(path="/app/../etc/passwd")
    _, departures = TaskSurface.of(_task([attack])).classify(attack)
    assert "target" in departures


def test_egress_host_is_its_own_surface():
    """Hosts must not be collapsed by directory prefix: two different hosts are
    two different surfaces, not one."""
    benign = _event(label=EventLabel.BENIGN, path="net:api.internal")
    attack = _event(path="net:198.51.100.7")
    surface = TaskSurface.of(_task([benign, attack]))
    klass, departures = surface.classify(attack)
    assert klass == SURFACE_LEAVING and "target" in departures
