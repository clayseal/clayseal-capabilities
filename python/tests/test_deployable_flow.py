"""In-scope data staging, closed on the deployable path.

`in_scope_exfiltration.md` measured the gap: against an oracle attacker the full
enforcement ladder's escaped-task set was byte-identical to `allow-all`, and the
whole attack was `read:/app/.env -> write:/app/README.md`. Two actions, both
inside the grant, granted tool, granted resource.

`StagingLadderEngine` closed it in replay with a coarse predicate: any
publication-class write after any secret-class read. That could not read content
because replay corpora have none, so its false-block rate was a non-measurement
(zero benign conjunctions across 20,299 events).

On the deployable path the content exists, so the predicate sharpens from "a
secret was read this session" to "this write carries it".
"""
from __future__ import annotations

from agentauth.capabilities.deployable_stack import DeployableStack
from agentauth.capabilities.monitor.action import Action
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.capabilities.broker import Outcome

SECRET = "AKIA0123456789ABCDEFQZ"


def _stack(**kw):
    return DeployableStack.from_goal(
        GoalSpec(query_id="q", summary="summarise the app and update the docs",
                 allow_resources=[]), **kw)


def _read_env(broker):
    broker.observe_output("read_file", SECRET, structured_fields={"value": SECRET},
                          source_path="/app/.env", containing_object="/app/.env")
    return broker


def _write(broker, content, path="/app/README.md", step=0):
    return broker.authorize(Action(
        step=step, tool="write_file", resource="workspace", verb="write",
        args={"file_path": path, "content": content}))


def test_the_stack_arms_confidentiality_by_default():
    """A mandate that declares no secrets is not silently unprotected, which is
    the clause `object_class.py` states as its reason for existing."""
    broker = _stack().broker
    assert broker.flow is not None
    assert broker.sensitivity.active


def test_staging_a_secret_into_a_published_artifact_steps_up():
    decision = _write(_read_env(_stack().broker), f"build notes {SECRET}")
    assert decision.outcome is Outcome.STEP_UP
    assert decision.layer == "flow"


def test_an_ordinary_documentation_edit_is_untouched():
    """The sharpening that matters. The coarse rung refused ANY publication
    write after ANY secret read, and a coding agent reads `.env` for config and
    edits a README constantly. Content derivation separates them."""
    decision = _write(_read_env(_stack().broker), "ordinary release notes")
    assert decision.outcome is Outcome.ALLOW


def test_nothing_fires_before_a_secret_is_read():
    assert _write(_stack().broker, f"notes {SECRET}").outcome is Outcome.ALLOW


def test_it_can_be_switched_off():
    """`enable_flow=False` for a caller who wants the previous behaviour, so the
    change is opt-out rather than imposed."""
    assert _stack(enable_flow=False).broker.flow is None


def test_a_declared_mandate_policy_wins_over_the_default_taxonomy():
    """The static patterns are a fallback, never an override: an operator who
    enumerated their own secrets gets exactly those."""
    from agentauth.capabilities.confidentiality import SensitivityPolicy

    declared = SensitivityPolicy(sensitive=("db:only-this",))
    broker = _stack(sensitivity=declared).broker
    assert broker.sensitivity.sensitive == ("db:only-this",)
