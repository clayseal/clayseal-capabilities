"""A resource-membership tier may refuse only when it can read the resource.

Both tiers that compile a goal into allowed resource classes guarded the empty
surface and neither guarded the disjoint one. Measured on `sleight`, where every
event is labelled `resource="workspace"` and the goal surface is compiled from
file paths, that refused 204 of 311 benign events in the authorization path and
13 of 18 benign trajectories in the detector, several at conformal p-values
above 0.5. These tests hold both tiers to the rule in `monitor/surface.py`.
"""
from __future__ import annotations

import pytest

from clayseal.capabilities.monitor.action import Action, Trajectory
from clayseal.capabilities.monitor.envelope import TypedGoalEnvelope
from clayseal.capabilities.monitor.surface import (
    in_surface,
    matches_surface,
    names_a_target,
    resource_readings,
    surface_class,
    surface_is_comparable,
)
from clayseal.capabilities.scoping.goal import GoalSpec

SURFACE = frozenset({"data", "home"})


def act(step: int, resource: str, *, path: str | None = None,
        tool: str = "Bash", verb: str = "write") -> Action:
    return Action(step=step, tool=tool, resource=resource, verb=verb,
                  args={}, meta={"path": path} if path else {})


# ------------------------------------------------------------- readings ---
def test_both_fields_are_read():
    readings = resource_readings(act(0, "workspace", path="/data/models/x"))
    assert readings == ("workspace", "data")


def test_a_blank_reading_is_dropped():
    assert resource_readings(act(0, "")) == ()


def test_a_match_on_the_path_is_a_match():
    """The information was always there; only the field being read was wrong."""
    assert in_surface(act(0, "workspace", path="/data/models/x"), SURFACE)


def test_a_match_on_neither_field_is_not_a_match():
    assert not in_surface(act(0, "workspace", path="/etc/shadow"), SURFACE)


# -------------------------------------------------------- comparability ---
def test_an_empty_surface_is_never_comparable():
    assert not surface_is_comparable(frozenset(), [act(0, "data")])


def test_a_surface_nothing_has_ever_matched_is_not_comparable():
    """The sleight shape: populated surface, disjoint vocabulary."""
    session = [act(0, "workspace"), act(1, "workspace"), act(2, "workspace")]
    assert not surface_is_comparable(SURFACE, session)


def test_one_matching_action_makes_the_session_comparable():
    session = [act(0, "workspace"), act(1, "data:models")]
    assert surface_is_comparable(SURFACE, session)


def test_comparability_is_session_level_not_per_action():
    """One matching action licenses the tier for the whole session.

    A novel LABEL is abstained on per action, because a bare word with no path
    names nothing a path-shaped surface can judge. What an attacker cannot do is
    relabel their way past a real target: the moment the action carries a path,
    the path is what decides.
    """
    session = [act(0, "data:models"), act(1, "invented-vocabulary")]
    assert surface_is_comparable(SURFACE, session)
    assert not matches_surface(session[1], SURFACE)
    assert in_surface(session[1], SURFACE)          # abstained, not refused

    relabelled = act(2, "invented-vocabulary", path="/etc/shadow")
    assert not in_surface(relabelled, SURFACE)      # the path still decides


# ------------------------------------------------- the two tiers, in situ ---
def _goal(resources: list[str]) -> GoalSpec:
    return GoalSpec(query_id="q", summary="do the task",
                    allow_resources=resources,
                    structured_intent={"kind": "task", "verbs": ["write"],
                                       "tools": ["Bash"]})


def test_typed_envelope_refuses_a_real_departure():
    env = TypedGoalEnvelope.from_goal(_goal(["/data/models/**"]))
    verdict = env.assess(act(0, "net:evil.example"), resources_comparable=True)
    assert not verdict.in_envelope


def test_typed_envelope_abstains_when_the_surface_never_matched():
    env = TypedGoalEnvelope.from_goal(_goal(["/data/models/**"]))
    assert env.assess(act(0, "workspace"), resources_comparable=False).in_envelope


def test_typed_envelope_reads_the_path_when_the_resource_is_opaque():
    env = TypedGoalEnvelope.from_goal(_goal(["/data/models/**"]))
    action = act(0, "workspace", path="/data/models/orion/final")
    assert env.assess(action, resources_comparable=True).in_envelope


def test_a_blank_resource_never_populates_the_surface():
    """A blank class makes an empty surface look populated, which refuses all."""
    env = TypedGoalEnvelope.from_goal(_goal([""]))
    assert "" not in env.allowed_resource_classes


def test_intent_envelope_abstains_on_a_disjoint_session():
    """End to end: the exact shape that denied 204 benign sleight events."""
    from clayseal.capabilities.monitor.intent_envelope import IntentEnvelope

    env = IntentEnvelope.from_goal(_goal(["/data/models/**", "/home/js/**"]))
    assert env.allowed_resource_classes
    traj = Trajectory(actions=[act(0, "workspace"), act(1, "workspace")],
                      goal=_goal(["/data/models/**"]))
    assert not env.surface_is_comparable(traj)
    for action in traj.actions:
        assert env._membership(action, resources_comparable=False) is None


def test_intent_envelope_still_refuses_once_the_surface_has_matched():
    from clayseal.capabilities.monitor.intent_envelope import IntentEnvelope

    env = IntentEnvelope.from_goal(_goal(["/data/models/**"]))
    traj = Trajectory(actions=[act(0, "data:models"), act(1, "net:evil.example")],
                      goal=_goal(["/data/models/**"]))
    assert env.surface_is_comparable(traj)
    off = env._membership(traj.actions[1], resources_comparable=True)
    assert off is not None and "outside the goal surface" in off.reason


# ------------------------------------------- the abstention, adversarially ---
def test_abstention_cannot_be_bought_by_never_matching():
    """The attack on the rule: keep the session incomparable, then act.

    An attacker who controls resource labels could try to keep the membership
    tier abstaining for a whole session by never naming anything in the goal
    surface. The tier does abstain. It does not follow that anything is gained,
    and the reason is worth stating rather than assuming: a session that never
    matches the surface is one where the tier would otherwise have refused
    EVERY action, benign work included. The choice on that session was never
    between enforcement and abstention, it was between refusing everything and
    refusing nothing, and what actually decides is the path scope in the floor.

    Measured, and this is the number that matters: on `redcode` 599 of 650
    sessions never become comparable, and surface-leaving containment there is
    717 of 717 with 0 of 344 benign events interrupted. The floor carries it.
    """
    surface = frozenset({"data", "home"})
    session = [act(i, "opaque-handle") for i in range(6)]
    assert not surface_is_comparable(surface, session)
    # Nothing in the session MATCHED, so the tier has nothing to say about any
    # of it. `matches_surface` is the strict question; `in_surface` folds in the
    # abstention, and conflating the two once let a session of nothing but
    # opaque labels report itself comparable.
    assert all(not matches_surface(a, surface) for a in session)


def test_doing_the_real_task_makes_the_tier_live_immediately():
    """The reason the abstention is narrow in practice.

    A session doing the work the goal describes touches a granted resource, and
    from that action onward the tier refuses normally. Measured across five
    corpora, every session that becomes comparable at all does so by its second
    action: 40 of 43 sleight sessions and all of agentharm, agentleak, asb and
    injecagent are live at action one.
    """
    surface = frozenset({"data", "home"})
    session = [act(0, "opaque-handle"), act(1, "workspace", path="/data/models/x")]
    assert surface_is_comparable(surface, session)
    assert not matches_surface(session[0], surface)


# ------------------------------------------------- unreadable is not absent ---
@pytest.mark.parametrize("resource", [
    ".env",                     # the canonical secrets file, and a bare dotfile
    "..\\..\\etc\\shadow",      # backslashes: no `:` and no `/` to split on
    "..", ".", "...",           # bare traversal components
    "/",                        # the root is a target, not the absence of one
])
def test_a_target_this_cannot_class_is_not_a_pass(resource):
    """The bypass this module was itself written to prevent, one level down.

    `resource_readings` returns nothing both when an action names no target and
    when it names one that cannot be classed. Reading the second as the first
    let `.env` and `..\\..\\etc\\shadow` through the membership tier outright.
    `the server did not say` and `the server said no` are different facts, and
    so are `named nothing` and `named something unreadable`.
    """
    action = act(0, resource)
    assert names_a_target(action)
    assert not in_surface(action, frozenset({"data", "home"}))


def test_an_action_naming_no_target_at_all_still_passes():
    """The genuine case the rule above must not swallow."""
    action = act(0, "")
    assert not names_a_target(action)
    assert in_surface(action, frozenset({"data", "home"}))


def test_a_backslash_is_a_separator():
    """This repository has had one backslash bypass already, in the deny-list.

    Anything that reads a path has to agree with whatever finally opens it.
    """
    assert surface_class("..\\..\\data\\ok") == ".."
    assert surface_class("\\etc\\shadow") == "etc"
    assert in_surface(act(0, "x", path="\\data\\models\\m"), frozenset({"data"}))


# ---------------------------------------------------- traversal and naming ---
@pytest.mark.parametrize("resource", [
    "data/../etc/shadow",
    "data/../../etc/shadow",
    "home/../etc/passwd",
    "data/./../etc/shadow",
    "data/x/../../etc/shadow",
    "data//../etc/shadow",
    "data\\..\\etc\\shadow",
])
def test_traversal_through_a_granted_prefix_is_not_in_surface(resource):
    """The worst defect this module has had, and a corpus can never find it.

    `data/../etc/shadow` classed as `data`, passed a surface granting `data`,
    and opened `/etc/shadow`. Five variants were live. `normpath` resolves the
    traversal before the class is taken, which is the right strength: it is
    textual, it cannot follow a symlink, and it must not try, because this is a
    pure function of a string and the floor does the filesystem check.
    """
    assert not in_surface(act(0, resource), frozenset({"data", "home"}))


def test_a_path_that_escapes_upward_resolves_to_a_traversal():
    """Conservative in the correct direction: it lands outside every surface a
    goal can produce, because `surface_from` never emits `..` from a real path."""
    assert surface_class("data/../../etc") == ".."
    assert not in_surface(act(0, "data/../../etc"), SURFACE)
    from clayseal.capabilities.monitor.surface import surface_from

    assert ".." not in surface_from(["/data/**", "../etc"])


def test_a_file_named_after_a_granted_directory_is_not_inside_it():
    """`data.txt` sits beside `data/`, not in it, and classed as `data`.

    `resource_class` splits on `.` so a host reads as its domain, which is right
    for a host and wrong for a filename. A scheme keeps that reading; a path
    takes its first component whole.
    """
    surface = frozenset({"data"})
    assert in_surface(act(0, "/data/models/x"), surface)
    assert not in_surface(act(0, "data.txt"), surface)
    assert not in_surface(act(0, "/data.txt"), surface)


@pytest.mark.parametrize("resource,expected", [
    ("net:evil.example", "net"),
    ("net:s3:orion-store", "net"),
    ("repo://a/b", "repo"),
    ("mcp:tool:send_email", "mcp:tool"),
    ("file:secrets/x", "file"),
    ("https://evil.example/x", "https"),
])
def test_every_scheme_keeps_its_reading(resource, expected):
    """The path rules must not rewrite a scheme on their way past."""
    assert surface_class(resource) == expected


# ------------------------------- an opaque label is abstained on, not refused ---
@pytest.mark.parametrize("resource", ["workspace", "session", "opaque-handle"])
def test_a_bare_label_with_no_path_names_nothing_a_surface_can_judge(resource):
    """`workspace` is not a place: it is what a harness or an MCP server calls
    the session, and the surface it is tested against holds `data` and `home`.

    Measured on sleight, 34 benign actions were HARD DENIED on the strength of
    such a label, in sessions made comparable by other actions that did carry
    paths. Fixing it took that corpus from 46.5% of benign sessions disrupted
    to 4.7%.
    """
    from clayseal.capabilities.monitor.surface import names_a_readable_target

    action = act(0, resource)
    assert not names_a_readable_target(action)
    assert in_surface(action, SURFACE)


@pytest.mark.parametrize("resource,path", [
    ("net:evil.example", None),
    ("evil.example", None),
    ("/etc/shadow", None),
    ("workspace", "/etc/shadow"),
])
def test_anything_that_does_name_a_target_is_still_judged(resource, path):
    """The abstention is narrow on purpose. A scheme says where it is going, a
    path says what it opens, and an opaque label with a path is judged on the
    path."""
    from clayseal.capabilities.monitor.surface import names_a_readable_target

    action = act(0, resource, path=path)
    assert names_a_readable_target(action)
    assert not in_surface(action, SURFACE)
