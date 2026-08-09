"""Runtime replanning, and the trust boundary that makes it safe.

Context: hard-denying plan deviations gives zero clean utility on AgentDyn, and
simply allowing them (`defer_allows_bound`) took travel from 5.6% to 27.8% ASR.
The plan check has to be extended rather than dropped, and the extension has to
be derived from trusted input only.

The load-bearing tests here are the boundary ones. If the replanner can see tool
output or argument values, an injection reaches the judge and the mechanism is
worse than useless, because it launders attacker influence through something
that looks like a policy decision.
"""
from __future__ import annotations

import pytest

from agentauth.capabilities.replan import (
    ActionShape,
    PlanExtender,
    deterministic_judge,
    llm_shape_judge,
    verb_class,
)

CATALOG = ["read_email", "send_email", "read_file", "transfer_money"]


def _extender(judge=None, **kw) -> PlanExtender:
    return PlanExtender(
        judge=judge or deterministic_judge({"observe", "communicate"}),
        goal="summarise my inbox and reply to Alice",
        catalog=CATALOG, **kw)


# --------------------------------------------------------------------------- #
# The trust boundary
# --------------------------------------------------------------------------- #
def test_the_judge_never_receives_argument_values():
    """The whole security argument. An injection lives in content, so content
    must not reach the judge."""
    seen = {}

    def spy(goal, catalog, shape):
        seen["goal"] = goal
        seen["catalog"] = catalog
        seen["shape"] = shape
        return True, "ok"

    _extender(judge=spy).consider("send_email", "send")
    assert isinstance(seen["shape"], ActionShape)
    assert set(vars(seen["shape"])) == {"tool", "verb_class"}, (
        "ActionShape must carry nothing but tool and verb class"
    )


def test_action_shape_cannot_carry_content():
    """Constructed from tool and verb alone, so a caller cannot pass values
    through even by accident."""
    shape = ActionShape.of("send_email", "send")
    assert shape.tool == "send_email" and shape.verb_class == "communicate"
    assert not hasattr(shape, "args")


def test_llm_prompt_contains_no_runtime_content():
    """Guards the prompt itself: adding tool output here would silently remove
    the boundary while every other test still passed."""
    captured = {}

    class FakeClient:
        class chat:
            class completions:
                @staticmethod
                def create(**kw):
                    captured["prompt"] = kw["messages"][0]["content"]
                    class R:
                        choices = [type("C", (), {"message": type(
                            "M", (), {"content": '{"required": true, "why": "y"}'})()})()]
                    return R()

    judge = llm_shape_judge(FakeClient(), "m")
    judge("summarise my inbox", CATALOG, ActionShape.of("send_email", "send"))
    prompt = captured["prompt"]
    assert "summarise my inbox" in prompt
    assert "send_email" in prompt
    for forbidden in ("attacker", "iban", "tool_result", "observation"):
        assert forbidden not in prompt.lower()


# --------------------------------------------------------------------------- #
# Behaviour
# --------------------------------------------------------------------------- #
def test_a_goal_consistent_shape_extends_the_plan():
    assert _extender().consider("send_email", "send").extended


def test_a_shape_outside_the_mandate_is_refused():
    verdict = _extender().consider("transfer_money", "transfer")
    assert not verdict.extended and "outside the mandate" in verdict.reason


def test_a_tool_outside_the_catalog_is_refused():
    verdict = _extender().consider("ssh", "execute")
    assert not verdict.extended and "not in the granted tool catalog" in verdict.reason


def test_a_cleared_shape_is_not_rejudged():
    calls = []

    def counting(goal, catalog, shape):
        calls.append(shape)
        return True, "ok"

    ext = _extender(judge=counting)
    for _ in range(5):
        assert ext.consider("send_email", "send").extended
    assert len(calls) == 1, "an agent sending five emails should be judged once"


def test_a_refusal_is_remembered():
    calls = []

    def counting(goal, catalog, shape):
        calls.append(shape)
        return False, "no"

    ext = _extender(judge=counting)
    for _ in range(5):
        assert not ext.consider("transfer_money", "transfer").extended
    assert len(calls) == 1


# --------------------------------------------------------------------------- #
# Bounds and failure modes
# --------------------------------------------------------------------------- #
def test_extensions_are_capped():
    """An unbounded extender converges on allow-all given a long enough
    session, which is the failure mode of every 'just ask the model' design."""
    ext = _extender(judge=lambda g, c, s: (True, "ok"), max_extensions=2)
    assert ext.consider("a", "read").extended
    assert ext.consider("b", "write").extended
    third = ext.consider("c", "send")
    assert not third.extended and "already extended" in third.reason


def test_the_judge_fails_closed():
    """A planner outage must not widen authority. The caller's existing deny
    path is the safe default."""
    class Broken:
        class chat:
            class completions:
                @staticmethod
                def create(**kw):
                    raise RuntimeError("planner down")

    judge = llm_shape_judge(Broken(), "m")
    ok, reason = judge("goal", CATALOG, ActionShape.of("send_email", "send"))
    assert not ok and "unavailable" in reason


def test_verb_classes_generalise_across_tools():
    """So that clearing 'this task needs to communicate' does not have to be
    re-judged per tool, while still not granting unrelated classes."""
    assert verb_class("send") == verb_class("post") == "communicate"
    assert verb_class("transfer") == verb_class("pay") == "move_value"
    assert verb_class("read") != verb_class("delete")


def test_extensions_are_observable():
    """An operator has to be able to see the plan growing, or this is an
    invisible widening of authority."""
    seen = []
    ext = _extender(judge=lambda g, c, s: (True, "ok"))
    ext.on_extend = seen.append
    ext.consider("send_email", "send")
    assert seen and seen[0].extended and seen[0].shape.tool == "send_email"
