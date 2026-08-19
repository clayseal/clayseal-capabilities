"""The planner is in the trusted computing base and used to fail open.

`allowed = sorted(names)` on any error admitted every tool in the catalog, which
is an undefended run reported as a defended one. `denial_diagnosis.md` records
that exact defect class once already: "the ablation ran with no defense at all …
reported 8/8 and a 50-point improvement".
"""
from __future__ import annotations

import json
import types

import pytest

from benchmarks.live.planner import LLMPlanner

TOOLS = [("read_file", "read a file"), ("search", "search"),
         ("send_money", "transfer funds"), ("delete_file", "delete")]
EFFECT_TOOLS = {"send_money", "delete_file"}


def _client(payload=None, raise_exc=None):
    class C:
        class chat:
            class completions:
                @staticmethod
                def create(**kw):
                    if raise_exc:
                        raise raise_exc
                    message = types.SimpleNamespace(content=json.dumps(payload))
                    return types.SimpleNamespace(
                        choices=[types.SimpleNamespace(message=message)])
    return C()


BROKEN = {
    "api raises": _client(raise_exc=RuntimeError("503 upstream")),
    "empty allowed_tools": _client({"allowed_tools": [], "plan": []}),
    "malformed shape": _client({"allowed_tools": {"a": 1}, "plan": "nope"}),
    "not a dict": _client(["a", "b"]),
    "null fields": _client({"allowed_tools": None, "plan": None}),
}


@pytest.mark.parametrize("name", sorted(BROKEN))
def test_a_broken_planner_never_admits_an_effect_tool(name):
    """The property that matters. Degraded is acceptable; allow-all is not."""
    allowed, env = LLMPlanner(BROKEN[name], "m").plan("do a thing", TOOLS)
    assert not (set(allowed) & EFFECT_TOOLS), f"{name} admitted an effect tool"
    assert env.degraded is True


@pytest.mark.parametrize("name", sorted(BROKEN))
def test_a_broken_planner_still_completes_the_run(name):
    """The stated reason for failing open was not to break the run. Preserved:
    the acquisition set is admitted so the agent can orient, and consequential
    actions fall outside the empty plan and step up."""
    allowed, env = LLMPlanner(BROKEN[name], "m").plan("do a thing", TOOLS)
    assert "read_file" in allowed and "search" in allowed
    assert env.phases == ()


def test_a_healthy_planner_is_unchanged():
    allowed, env = LLMPlanner(
        _client({"allowed_tools": ["read_file", "send_money"],
                 "plan": ["read_file", "send_money"]}), "m").plan("q", TOOLS)
    assert "send_money" in allowed
    assert env.degraded is False


def test_the_degraded_reason_is_recorded():
    """A degraded task must be attributable, not merely flagged."""
    _, env = LLMPlanner(BROKEN["api raises"], "m").plan("q", TOOLS)
    assert "503 upstream" in env.planner_error


def test_the_cache_is_keyed_on_the_tool_catalogue():
    """`self._cache[query]` returned a plan built for a different catalogue
    whenever the same request ran against a different tool set, which is exactly
    what the ablation sweeps do."""
    planner = LLMPlanner(
        _client({"allowed_tools": ["read_file", "send_money", "delete_file"],
                 "plan": []}), "m")
    a, _ = planner.plan("same query", [("read_file", "r"), ("send_money", "t")])
    b, _ = planner.plan("same query", [("read_file", "r"), ("delete_file", "d")])
    assert "send_money" in a and "send_money" not in b
    assert len(planner._cache) == 2


def test_a_transient_failure_is_retried_before_degrading():
    """One flaky call should not cost the run its defense."""
    calls = {"n": 0}

    class Flaky:
        class chat:
            class completions:
                @staticmethod
                def create(**kw):
                    calls["n"] += 1
                    if calls["n"] < 2:
                        raise RuntimeError("transient")
                    message = types.SimpleNamespace(content=json.dumps(
                        {"allowed_tools": ["read_file", "send_money"], "plan": []}))
                    return types.SimpleNamespace(
                        choices=[types.SimpleNamespace(message=message)])

    allowed, env = LLMPlanner(Flaky(), "m").plan("q", TOOLS)
    assert env.degraded is False
    assert "send_money" in allowed
    assert calls["n"] == 2
