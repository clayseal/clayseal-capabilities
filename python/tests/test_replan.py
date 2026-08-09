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

from decimal import Decimal

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


# --------------------------------------------------------------------------- #
# Broker integration: the extender must sit in front of the deny, not replace it
# --------------------------------------------------------------------------- #
def _broker(**kw):
    from agentauth.capabilities.broker import SessionBroker
    from agentauth.capabilities.scoping.goal import GoalSpec
    from agentauth.core.task_scope import TaskScope

    return SessionBroker(
        goal=GoalSpec(query_id="q", summary="summarise the inbox"),
        scope=TaskScope(allowed_resources=["mcp:tool:read_email"], allowed_actions=[]),
        **kw)


def _action(tool="send_email", verb="send"):
    from agentauth.capabilities.monitor import Action

    return Action(step=0, tool=tool, resource=f"mcp:tool:{tool}", verb=verb,
                  args={"to": "someone@example.com"})


def test_broker_without_an_extender_is_unchanged():
    """Default behaviour must not move: this is opt-in."""
    from agentauth.capabilities.broker import Outcome

    assert _broker().authorize(_action()).outcome is not Outcome.ALLOW


def test_a_floor_denial_never_reaches_the_extender():
    """The security property that keeps this from becoming defer_allows_bound.

    Replanning grows the PLAN. It has no authority over scope, protected zones,
    destination binding or budgets, so an action the floor refuses must be
    refused whatever the extender would have said. Verified by giving the
    extender an unconditional yes and checking it is never even asked.
    """
    from agentauth.capabilities.broker import Outcome
    from agentauth.capabilities.replan import ReplanVerdict

    consulted = []

    class AlwaysYes:
        def consider(self, tool, verb):
            consulted.append((tool, verb))
            return ReplanVerdict(True, "yes to everything")

    # `send_email` is outside this broker's resource scope, so the floor denies.
    decision = _broker(plan_extender=AlwaysYes()).authorize(_action())
    assert decision.outcome is not Outcome.ALLOW
    assert not consulted, (
        "the extender was consulted on a floor denial; replanning must not be "
        "able to rescue an action the floor refused"
    )


def test_a_refused_extension_leaves_the_denial_intact():
    from agentauth.capabilities.broker import Outcome
    from agentauth.capabilities.replan import ReplanVerdict

    class Refuse:
        def consider(self, tool, verb):
            return ReplanVerdict(False, "not implied by the goal")

    assert _broker(plan_extender=Refuse()).authorize(_action()).outcome is not Outcome.ALLOW


def test_an_extension_is_recorded_on_the_audit_chain():
    """A plan that grew silently is an invisible widening of authority.

    Exercised on the extender rather than through the broker, because reaching
    the envelope stage needs a compiled envelope and the property under test is
    that every extension is observable.
    """
    seen = []
    ext = _extender(judge=lambda g, c, s: (True, "goal implies communicating"))
    ext.on_extend = seen.append
    ext.consider("send_email", "send")
    assert seen and "goal implies" in seen[0].reason


def test_an_advisory_scope_may_be_widened_but_a_mandate_may_not():
    """The distinction that resolves the tension above.

    `allowed_resources` in the live path is the LLM planner's GUESS at which
    tools the task needs. On an open-ended task it cannot know: AgentDyn
    shopping needed `verify_shopping_account` and `cart_total`, and their
    absence was the entire residual block set once plan conformance was fixed.
    Extending a guess from the sealed goal is legitimate.

    A mandate-derived resource list is an authorization, and no runtime judgment
    may widen it. Nothing in the code expressed that difference until the test
    above caught the ambiguity, so it is now an explicit flag that defaults to
    the safe reading.
    """
    from agentauth.capabilities.broker import Outcome
    from agentauth.capabilities.replan import ReplanVerdict

    class AlwaysYes:
        def consider(self, tool, verb):
            return ReplanVerdict(True, "goal implies this")

    # Mandate-derived (the default): stays refused.
    strict = _broker(plan_extender=AlwaysYes())
    assert strict.authorize(_action()).outcome is not Outcome.ALLOW

    # Planner-derived: may grow.
    advisory = _broker(plan_extender=AlwaysYes(), scope_is_advisory=True)
    assert advisory.authorize(_action()).outcome is Outcome.ALLOW


def test_widening_the_scope_does_not_disable_the_other_floor_checks():
    """Extending which TOOL may be used must not extend where it may point."""
    from agentauth.capabilities.broker import Outcome
    from agentauth.capabilities.monitor import Action
    from agentauth.capabilities.replan import ReplanVerdict

    class AlwaysYes:
        def consider(self, tool, verb):
            return ReplanVerdict(True, "yes")

    broker = _broker(plan_extender=AlwaysYes(), scope_is_advisory=True)
    protected = Action(step=0, tool="write_file", resource="mcp:tool:write_file",
                       verb="write", args={"file_path": "/home/u/.ssh/id_rsa"})
    assert broker.authorize(protected).outcome is not Outcome.ALLOW


# --------------------------------------------------------------------------- #
# An extended action pays. Found by an adversarial audit, not by the tests above.
# --------------------------------------------------------------------------- #
def test_an_extended_action_still_spends_its_budget():
    """The defect: replanning defeated two rungs of the ladder.

    `authorize` rolled the action back before consulting the extender, which
    released the value and call reservations and popped the action off the
    trajectory. The extender then returned ALLOW without re-reserving. Every
    extended action was therefore free: the ledgers never incremented, so a
    cumulative ceiling could never be reached however many actions were
    extended, and the action was invisible to the trajectory detector and to
    every later feasibility check.

    Nothing above caught it because no test built a broker with both a budget
    and an extender.
    """
    from agentauth.capabilities.broker import Outcome, SessionBroker
    from agentauth.capabilities.call_budget import CallBudgetConfig, SessionCallBudget
    from agentauth.capabilities.replan import ReplanVerdict
    from agentauth.capabilities.scoping.goal import GoalSpec
    from agentauth.capabilities.value_budget import SessionValueBudget, ValueBudgetConfig
    from agentauth.capabilities.monitor import Action
    from agentauth.core.task_scope import TaskScope

    class AlwaysYes:
        def consider(self, tool, verb):
            return ReplanVerdict(True, "goal implies this")

    def _broker_with_budget():
        return SessionBroker(
            goal=GoalSpec(query_id="q", summary="pay the invoices"),
            scope=TaskScope(allowed_resources=["mcp:tool:read_email"], allowed_actions=[]),
            value_budget=SessionValueBudget(config=ValueBudgetConfig(
                ceilings={"usd": Decimal("1000")},
                tracked={"transfer_money": ("amount", "usd")})),
            call_budget=SessionCallBudget(config=CallBudgetConfig(
                ceilings={"transfers": 10},
                tracked={"transfer_money": "transfers"})),
            plan_extender=AlwaysYes(), scope_is_advisory=True)

    broker = _broker_with_budget()
    allowed = 0
    for i in range(10):
        decision = broker.authorize(Action(
            step=i, tool="transfer_money", resource="mcp:tool:transfer_money",
            verb="transfer", args={"amount": "400", "to": "acct-1"}))
        if decision.outcome is Outcome.ALLOW:
            allowed += 1

    assert allowed <= 2, (
        f"{allowed} transfers of 400 allowed against a 1000 ceiling; extended "
        f"actions are not spending their budget"
    )


def test_an_extended_action_stays_on_the_trajectory():
    """The other half: a rolled-back action is invisible to the behavioural
    layer, so an attacker whose actions are all extension-approved leaves no
    trace for the detector or for any later feasibility check."""
    from agentauth.capabilities.broker import Outcome, SessionBroker
    from agentauth.capabilities.replan import ReplanVerdict
    from agentauth.capabilities.scoping.goal import GoalSpec
    from agentauth.capabilities.monitor import Action
    from agentauth.core.task_scope import TaskScope

    class AlwaysYes:
        def consider(self, tool, verb):
            return ReplanVerdict(True, "yes")

    broker = SessionBroker(
        goal=GoalSpec(query_id="q", summary="summarise the inbox"),
        scope=TaskScope(allowed_resources=["mcp:tool:read_email"], allowed_actions=[]),
        plan_extender=AlwaysYes(), scope_is_advisory=True)
    for i in range(4):
        broker.authorize(Action(
            step=i, tool="send_email", resource="mcp:tool:send_email",
            verb="send", args={"to": "someone@example.com"}))
    assert len(broker._trajectory.actions) == 4


def test_replanning_cannot_rescue_an_infeasible_goal():
    """Deviation and infeasibility are different signals.

    A deviation says the agent took a step the compiled plan did not list, which
    on an open-ended task is usually the planner failing to enumerate. An
    infeasibility says the action steered the mission out of reach. No amount of
    shape plausibility restores a goal condition that can no longer be met, so
    the extender is consulted for the first and not the second.
    """
    from agentauth.capabilities.broker import Outcome, SessionBroker
    from agentauth.capabilities.replan import ReplanVerdict
    from agentauth.capabilities.scoping.goal import GoalSpec
    from agentauth.capabilities.monitor import Action
    from agentauth.core.task_scope import TaskScope

    consulted = []

    class AlwaysYes:
        def consider(self, tool, verb):
            consulted.append((tool, verb))
            return ReplanVerdict(True, "yes")

    class Infeasible:
        def last_deviation(self, trajectory):
            return None

        def feasible(self, trajectory):
            return False, "the goal can no longer be met"

    broker = SessionBroker(
        goal=GoalSpec(query_id="q", summary="summarise the inbox"),
        scope=TaskScope(allowed_resources=["mcp:tool:send_email"], allowed_actions=[]),
        intent_envelope=Infeasible(),
        plan_extender=AlwaysYes(), scope_is_advisory=True)
    decision = broker.authorize(Action(
        step=0, tool="send_email", resource="mcp:tool:send_email",
        verb="send", args={"to": "someone@example.com"}))
    assert decision.outcome is not Outcome.ALLOW
    assert not consulted, "the extender was asked to rescue an infeasible goal"


def test_scope_extension_does_not_mutate_the_callers_scope():
    """The extension set is session-local.

    It used to append to `scope.allowed_resources`, which is the caller's own
    TaskScope object, so authority granted by one session's replanning outlived
    the broker and leaked into every other session sharing that instance.
    """
    from agentauth.capabilities.broker import Outcome, SessionBroker
    from agentauth.capabilities.replan import ReplanVerdict
    from agentauth.capabilities.scoping.goal import GoalSpec
    from agentauth.capabilities.monitor import Action
    from agentauth.core.task_scope import TaskScope

    class AlwaysYes:
        def consider(self, tool, verb):
            return ReplanVerdict(True, "yes")

    shared = TaskScope(allowed_resources=["mcp:tool:read_email"], allowed_actions=[])
    before = list(shared.allowed_resources)

    first = SessionBroker(goal=GoalSpec(query_id="q", summary="s"), scope=shared,
                          plan_extender=AlwaysYes(), scope_is_advisory=True)
    assert first.authorize(_action()).outcome is Outcome.ALLOW
    assert shared.allowed_resources == before, "the caller's scope was mutated"

    # A second session sharing the scope must not inherit the grant.
    second = SessionBroker(goal=GoalSpec(query_id="q", summary="s"), scope=shared)
    assert second.authorize(_action()).outcome is not Outcome.ALLOW


def test_one_cleared_shape_does_not_admit_unlimited_resources():
    """`max_extensions` bounds SHAPES, and one shape admits many resources.

    Without an independent cap, a single "this goal may write" verdict let every
    write target in the catalog through.
    """
    from agentauth.capabilities.broker import Outcome, SessionBroker
    from agentauth.capabilities.replan import ReplanVerdict
    from agentauth.capabilities.scoping.goal import GoalSpec
    from agentauth.capabilities.monitor import Action
    from agentauth.core.task_scope import TaskScope

    class AlwaysYes:
        def consider(self, tool, verb):
            return ReplanVerdict(True, "yes")

    broker = SessionBroker(
        goal=GoalSpec(query_id="q", summary="s"),
        scope=TaskScope(allowed_resources=["mcp:tool:read_email"], allowed_actions=[]),
        plan_extender=AlwaysYes(), scope_is_advisory=True,
        max_scope_extensions=3)
    allowed = 0
    for i in range(20):
        decision = broker.authorize(Action(
            step=i, tool=f"write_tool_{i}", resource=f"mcp:tool:write_tool_{i}",
            verb="write", args={"body": "x"}))
        allowed += decision.outcome is Outcome.ALLOW
    assert allowed <= 3, f"{allowed} distinct resources admitted under a cap of 3"


def test_a_consequential_off_plan_action_needs_a_bound_destination_to_be_replanned():
    """The interlock. Measured, not assumed.

    Without it, replanning is `defer_allows_bound` under another name and fails
    the same way: on AgentDojo travel it took ASR from 11.1% to 22.2% while
    taking clean utility from 50.0% to 100.0%. A travel-booking goal plausibly
    implies sending and booking, so an injected action of that shape passes the
    shape check and only its destination distinguishes it.

    The two checks are independent by design. An attacker needs both a shape the
    goal implies AND a destination the floor accepts, and dropping either leaves
    the shape check solely responsible for containment, which it cannot carry.
    """
    from agentauth.capabilities.broker import Outcome, SessionBroker
    from agentauth.capabilities.hardening.egress_policy import EgressPolicy
    from agentauth.capabilities.monitor import Action
    from agentauth.capabilities.replan import ReplanVerdict
    from agentauth.capabilities.scoping.goal import GoalSpec
    from agentauth.core.task_scope import TaskScope

    consulted = []

    class AlwaysYes:
        def consider(self, tool, verb):
            consulted.append((tool, verb))
            return ReplanVerdict(True, "the goal implies sending")

    class OffPlan:
        def last_deviation(self, trajectory):
            return type("D", (), {"reason": "send_email not in the compiled plan"})()

        def feasible(self, trajectory):
            return True, ""

    def _broker(egress):
        return SessionBroker(
            goal=GoalSpec(query_id="q", summary="book my trip"),
            scope=TaskScope(allowed_resources=["mcp:tool:send_email"], allowed_actions=[]),
            egress=egress, intent_envelope=OffPlan(),
            plan_extender=AlwaysYes(), scope_is_advisory=True)

    def _send(to):
        return Action(step=0, tool="send_email", resource="mcp:tool:send_email",
                      verb="send", args={"to": to})

    egress = EgressPolicy(bind_recipients=True, allow_all=False,
                          allowed_recipients={"agent@travel.example"},
                          allowed_domains={"travel.example"})

    # The injected destination never clears the floor, so it never reaches the
    # extender and stays refused.
    consulted.clear()
    assert _broker(egress).authorize(_send("attacker@evil.test")).outcome is not Outcome.ALLOW

    # The goal's own destination clears the floor, so the plan may grow to cover it.
    consulted.clear()
    assert _broker(egress).authorize(_send("agent@travel.example")).outcome is Outcome.ALLOW
    assert consulted, "a bound destination should have reached the extender"


def test_replanning_without_any_egress_policy_cannot_pass_a_consequential_action():
    """With no binding floor the intent envelope is the only thing between an
    injected send and the attacker's address."""
    from agentauth.capabilities.broker import Outcome, SessionBroker
    from agentauth.capabilities.monitor import Action
    from agentauth.capabilities.replan import ReplanVerdict
    from agentauth.capabilities.scoping.goal import GoalSpec
    from agentauth.core.task_scope import TaskScope

    class AlwaysYes:
        def consider(self, tool, verb):
            return ReplanVerdict(True, "yes")

    class OffPlan:
        def last_deviation(self, trajectory):
            return type("D", (), {"reason": "off plan"})()

        def feasible(self, trajectory):
            return True, ""

    broker = SessionBroker(
        goal=GoalSpec(query_id="q", summary="book my trip"),
        scope=TaskScope(allowed_resources=["mcp:tool:send_email"], allowed_actions=[]),
        egress=None, intent_envelope=OffPlan(),
        plan_extender=AlwaysYes(), scope_is_advisory=True)
    decision = broker.authorize(Action(
        step=0, tool="send_email", resource="mcp:tool:send_email",
        verb="send", args={"to": "attacker@evil.test"}))
    assert decision.outcome is not Outcome.ALLOW
